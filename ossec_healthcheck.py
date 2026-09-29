#!/usr/bin/env python3
"""
ossec_healthcheck.py - health checks for a Linux OSSEC HIDS install (server, local or agent).

Checks (which run depends on the install type)
  permissions   warns when not run as root (/var/ossec is root:ossec 0550)
  install       install dir, version and type from /etc/ossec-init.conf
  daemons       required daemons running for this type, recent restarts, stale PID files
  queue         analysis queue socket present
  client_keys   server: key count; agent: registered; duplicates; file permissions
  agents        server: agents by state, disconnected agents named
  listener      server: something listening on each configured <remote> port
  connection    agent: most recent connect/disconnect event in ossec.log
  alerts        server/local: alerts.log still being written
  ossec_log     ERROR/CRITICAL lines in ossec.log within a time window + known trouble
  resources     CPU saturation and memory of OSSEC daemons, system memory
  disk          space and inodes on the OSSEC partition
  config_test   each daemon's `-t` config test + verify-agent-conf (--validate-config)

Output
  default       readable report: problems first, each with a suggested next step,
                then a one-line-per-check list of what's healthy
  --compact     one line per check; the first line is the overall status (Nagios-style)
  --json        one JSON object on one line (SIEM scripted inputs, jq)

Stdlib only, Python 3.6+. Exit codes follow the Nagios plugin convention
(0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN) in every output mode.

Examples
  sudo ./ossec_healthcheck.py
  sudo ./ossec_healthcheck.py --validate-config -v
  sudo ./ossec_healthcheck.py --agent-crit-pct 10 --log-window 6 --compact
"""

import argparse
import collections
import functools
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timedelta

OK, WARN, CRIT, UNKNOWN, SKIP = "OK", "WARNING", "CRITICAL", "UNKNOWN", "SKIPPED"
RANK = {SKIP: -1, OK: 0, UNKNOWN: 1, WARN: 2, CRIT: 3}
EXIT_CODES = {SKIP: 0, OK: 0, WARN: 1, CRIT: 2, UNKNOWN: 3}
COLORS = {OK: "32", WARN: "33", CRIT: "31", UNKNOWN: "35", SKIP: "2"}
SYMBOLS = {OK: "\u2714", WARN: "\u26a0", CRIT: "\u2716", UNKNOWN: "?", SKIP: "\u2013"}
ASCII_SYMBOLS = {OK: "+", WARN: "!", CRIT: "x", UNKNOWN: "?", SKIP: "-"}
HEADLINES = {OK: "All good", WARN: "Needs attention", CRIT: "Problems found",
             UNKNOWN: "Some checks couldn't run"}
CLK_TCK = float(os.sysconf("SC_CLK_TCK"))

PRODUCT = "OSSEC"
TITLES = {
    "privileges": "Permissions", "install": "OSSEC install", "daemons": "OSSEC daemons",
    "queue": "Event queue", "client_keys": "Agent keys", "agents": "Agents",
    "listener": "Agent listener", "connection": "Connection to server",
    "alerts": "Alert output", "ossec_log": "ossec.log errors", "resources": "CPU and memory",
    "disk": "Disk space", "config_test": "Config validation",
}

CORE_DAEMONS = {
    "server": ["ossec-analysisd", "ossec-remoted", "ossec-logcollector",
               "ossec-syscheckd", "ossec-monitord"],
    "local": ["ossec-analysisd", "ossec-logcollector", "ossec-syscheckd", "ossec-monitord"],
    "agent": ["ossec-agentd", "ossec-logcollector", "ossec-syscheckd"],
}
OPTIONAL_DAEMONS = ["ossec-csyslogd", "ossec-dbd", "ossec-agentlessd", "ossec-authd",
                    "ossec-reportd"]

LOG_LINE_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) (\S+?):? (.*)$")
LEVEL_RE = re.compile(r"^(CRITICAL|ERROR|WARN(?:ING)?|INFO|DEBUG)\b", re.I)
# (pattern, what it means, what to do)
KNOWN_ISSUES = [
    (re.compile(r"queue (is )?full|buffer (is )?full|flood", re.I),
     "The event queue or buffer filled up, so events were dropped",
     "Look for a noisy log source flooding OSSEC, or raise the queue/buffer settings."),
    (re.compile(r"duplicated? (error|counter)", re.I),
     "An agent sent duplicate message counters - usually a cloned or re-registered agent",
     "Remove that agent's file under queue/rids/ on the server and the agent, then restart both."),
    (re.compile(r"incorrectly formatt?ed message|invalid (id|key)|error decrypting", re.I),
     "Messages arrived from agents with unknown or mismatched keys",
     "Re-import the key on the affected agent, or re-register it."),
    (re.compile(r"too many open files|no space left|cannot allocate memory", re.I),
     "The host ran out of a resource (disk, memory or open files)",
     "Free up disk or memory, or raise the open-files limit for OSSEC."),
]
AGENT_UP_RE = re.compile(r"connected to (the )?server|server responded", re.I)
AGENT_DOWN_RE = re.compile(r"waiting for server reply|server unavailable|lost connection|"
                           r"unable to connect|trying to connect", re.I)


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #

def title_for(check):
    base, _, arg = check.partition(":")
    if arg:
        return "%s %s" % (TITLES.get(base, base), arg)
    return TITLES.get(base, base.replace("_", " ").capitalize())


def result(check, status, summary, issues=(), advice=(), notes=(), examples=(), **details):
    """One check outcome. summary = current state; issues = what's wrong (sentences);
    advice = what to do next; notes = FYI remarks that don't change the status."""
    issues, notes = list(issues), list(notes)
    message = summary
    if issues:
        message += " - " + " ".join(issues)
    if notes:
        message += " (" + " ".join(notes) + ")"
    return {"check": check, "title": title_for(check), "status": status, "summary": summary,
            "issues": issues, "advice": list(dict.fromkeys(advice)), "notes": notes,
            "examples": list(examples), "message": message, "details": details}


class Findings(object):
    """Collects the problems found by one check; the status only ever escalates."""

    def __init__(self):
        self.status, self.issues, self.advice = OK, [], []

    def add(self, status, issue, advice=None):
        self.status = worst(self.status, status)
        self.issues.append(issue)
        if advice:
            self.advice.append(advice)


def worst(*statuses):
    return max(statuses, key=lambda s: RANK[s])


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #

def run(cmd, timeout=30):
    """Run a command; return (returncode, stdout, stderr). returncode is None if it didn't run."""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              encoding="utf-8", errors="replace", timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return None, "", "timed out after %ds" % timeout
    except (OSError, ValueError) as exc:
        return None, "", str(exc)


def read_text(path, default=None):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def tail_lines(path, max_bytes):
    """Last lines of a file without reading all of it."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - max_bytes))
        data = fh.read()
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[1:] if size > max_bytes and lines else lines  # first line may be partial


def last_line(text):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return lines[-1] if lines else ""


def system_uptime():
    return float((read_text("/proc/uptime") or "0").split()[0])


def proc_argv(pid):
    raw = read_text("/proc/%d/cmdline" % pid, "")
    return [a for a in raw.split("\0") if a] if raw else []


@functools.lru_cache(maxsize=1)
def process_table():
    """{pid: (argv[0] basename, comm)} for every process, read once per run."""
    table = {}
    for entry in os.listdir("/proc"):
        if entry.isdigit() and int(entry) != os.getpid():
            argv = proc_argv(int(entry))
            comm = (read_text("/proc/%s/comm" % entry) or "").strip()
            table[int(entry)] = (os.path.basename(argv[0]) if argv else "", comm)
    return table


def find_processes(name):
    """PIDs whose argv[0] basename, or 15-char kernel comm, equals `name`."""
    return sorted(pid for pid, (argv0, comm) in process_table().items()
                  if argv0 == name or comm == name[:15])


def proc_stat(path):
    raw = read_text(path)
    if not raw:
        return None
    fields = raw[raw.rfind(")") + 2:].split()  # fields[0] is field 3 ("state") in proc(5)
    try:
        return {"ticks": int(fields[11]) + int(fields[12]), "start": int(fields[19])}
    except (IndexError, ValueError):
        return None


def proc_uptime(pid):
    st = proc_stat("/proc/%d/stat" % pid)
    return system_uptime() - st["start"] / CLK_TCK if st else None


def proc_status(pid):
    out = {}
    for line in (read_text("/proc/%d/status" % pid) or "").splitlines():
        key, _, value = line.partition(":")
        if value.strip().endswith("kB"):
            out[key] = int(value.split()[0])
    return out


def thread_cpu_ticks(pid):
    ticks = {}
    try:
        tids = os.listdir("/proc/%d/task" % pid)
    except OSError:
        return ticks
    for tid in tids:
        st = proc_stat("/proc/%d/task/%s/stat" % (pid, tid))
        if st:
            ticks[(pid, int(tid))] = st["ticks"]
    return ticks


def meminfo():
    out = {}
    for line in (read_text("/proc/meminfo") or "").splitlines():
        key, _, value = line.partition(":")
        if value.split():
            out[key] = int(value.split()[0])
    return out


def plural(n, word, many=None):
    return "%s %s" % ("{:,}".format(n), word if n == 1 else (many or word + "s"))


def fmt_duration(seconds):
    s = int(max(seconds, 0))
    if s < 60:
        return plural(s, "second")
    if s < 3600:
        return plural(s // 60, "minute")
    if s < 86400:
        hours, minutes = divmod(s // 60, 60)
        return plural(hours, "hour") + (" " + plural(minutes, "minute") if minutes and hours < 6 else "")
    days, hours = divmod(s // 3600, 24)
    return plural(days, "day") + (" " + plural(hours, "hour") if hours and days < 3 else "")


def ago(seconds):
    return "just now" if seconds < 5 else "%s ago" % fmt_duration(seconds)


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f TB" % n


def existing_parent(path):
    path = os.path.abspath(path)
    while not os.path.exists(path) and path != "/":
        path = os.path.dirname(path)
    return path


def check_disk(path, warn_pct, crit_pct, cleanup_advice):
    target = existing_parent(path)
    usage = shutil.disk_usage(target)
    denom = usage.used + usage.free
    space_pct = usage.used * 100.0 / denom if denom else 0.0
    vfs = os.statvfs(target)
    inode_pct = (vfs.f_files - vfs.f_ffree) * 100.0 / vfs.f_files if vfs.f_files else 0.0
    f = Findings()
    for pct, issue in ((space_pct, "The disk is %.0f%% full." % space_pct),
                       (inode_pct, "%.0f%% of inodes are used - many small files can exhaust "
                                   "these before space runs out." % inode_pct)):
        if pct >= warn_pct:
            f.add(CRIT if pct >= crit_pct else WARN, issue, cleanup_advice)
    summary = "%.0f%% used, %s free, %.0f%% of inodes used (%s)" % (
        space_pct, fmt_bytes(usage.free), inode_pct, target)
    return result("disk", f.status, summary, f.issues, f.advice, path=target,
                  space_used_pct=round(space_pct, 1), free_bytes=usage.free,
                  inodes_used_pct=round(inode_pct, 1))


def parse_log_time(line):
    m = LOG_LINE_RE.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #

def read_init_conf(path):
    info = {}
    for line in (read_text(path) or "").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            info[key.strip()] = value.strip().strip('"')
    return info


def conf_values(text, tag):
    return [v.strip() for v in re.findall(r"<%s>\s*(.*?)\s*</%s>" % (tag, tag), text, re.S)]


def first(values, default):
    return values[0] if values else default


def discover(args):
    init = read_init_conf("/etc/ossec-init.conf")
    home = args.ossec_dir or init.get("DIRECTORY") or "/var/ossec"

    def has_bin(name):
        return os.path.exists(os.path.join(home, "bin", name))

    mode = (args.mode or init.get("TYPE", "")).lower()
    if mode not in CORE_DAEMONS:
        mode = ("server" if has_bin("ossec-remoted") else
                "agent" if has_bin("ossec-agentd") else
                "local" if has_bin("ossec-analysisd") else None)

    conf, conf_state = "", "ok"
    try:
        with open(os.path.join(home, "etc", "ossec.conf"), "r", errors="replace") as fh:
            conf = re.sub(r"<!--.*?-->", "", fh.read(), flags=re.S)   # drop XML comments
    except FileNotFoundError:
        conf_state = "missing"
    except OSError:
        conf_state = "unreadable"

    listeners = []
    for block in re.findall(r"<remote>(.*?)</remote>", conf, re.S):
        connection = first(conf_values(block, "connection"), "secure").lower()
        port = first(conf_values(block, "port"), "1514" if connection == "secure" else "514")
        protocol = first(conf_values(block, "protocol"), "udp").lower()
        if port.isdigit():
            listeners.append({"connection": connection, "port": int(port), "protocol": protocol})

    client = " ".join(re.findall(r"<client>(.*?)</client>", conf, re.S))
    servers = (conf_values(client, "server-ip") + conf_values(client, "server-hostname")
               + conf_values(client, "address"))

    try:
        log_lines = tail_lines(os.path.join(home, "logs", "ossec.log"), args.log_bytes)
    except OSError:
        log_lines = None

    return {
        "home": home, "mode": mode, "init": init, "conf_state": conf_state,
        "email_enabled": bool(re.search(r"<email_notification>\s*yes\s*</email_notification>",
                                        conf, re.I)),
        # <active-response><disabled>yes</disabled></active-response> => ossec-execd exits
        "ar_disabled": bool(re.search(r"<active-response>(?:(?!</active-response>).)*?"
                                      r"<disabled>\s*yes\s*</disabled>", conf, re.S | re.I)),
        "listeners": listeners, "servers": servers, "log_lines": log_lines,
    }


def expected_daemons(ctx):
    names = list(CORE_DAEMONS[ctx["mode"]])
    if not ctx["ar_disabled"]:
        names.append("ossec-execd")
    if ctx["mode"] != "agent" and ctx["email_enabled"]:
        names.append("ossec-maild")
    return names


def agent_port(ctx):
    secure = [l for l in ctx["listeners"] if l["connection"] == "secure"]
    return "%s/%d" % (secure[0]["protocol"], secure[0]["port"]) if secure else "udp/1514"


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

def check_privileges():
    if os.geteuid() == 0:
        return []
    return result("privileges", WARN, "Not running as root, so most of /var/ossec is unreadable",
                  advice=["Re-run with sudo for complete results."])


def check_install(ctx):
    home = ctx["home"]
    if not os.path.isdir(home):
        return result("install", CRIT, "%s doesn't exist" % home,
                      advice=["Pass --ossec-dir if OSSEC is installed somewhere else."])
    if ctx["conf_state"] == "unreadable":
        return result("install", UNKNOWN, "Can't read %s/etc/ossec.conf" % home,
                      advice=["Re-run with sudo."])
    if ctx["conf_state"] == "missing":
        return result("install", CRIT, "%s/etc/ossec.conf is missing" % home,
                      advice=["Restore ossec.conf from backup - OSSEC can't start without it."])
    if not ctx["mode"]:
        return result("install", UNKNOWN, "Couldn't tell whether this is a server, agent or "
                      "local install", advice=["Pass --mode server, agent or local."])
    name = ctx["init"].get("NAME", "OSSEC")
    version = ctx["init"].get("VERSION", "(version unknown)")
    return result("install", OK, "%s %s, %s install in %s" % (name, version, ctx["mode"], home),
                  version=version, mode=ctx["mode"], home=home,
                  email_enabled=ctx["email_enabled"], active_response_disabled=ctx["ar_disabled"])


def stale_pid_files(ctx):
    stale = []
    run_dir = os.path.join(ctx["home"], "var", "run")
    try:
        names = os.listdir(run_dir)
    except OSError:
        return stale
    for name in names:
        m = re.match(r"^(.+)-(\d+)\.pid$", name)
        if m and int(m.group(2)) not in find_processes(m.group(1)):
            stale.append(name)
    return stale


def check_daemons(ctx, args):
    expected = expected_daemons(ctx)
    running = {name: find_processes(name) for name in expected + OPTIONAL_DAEMONS}
    missing = [n for n in expected if not running[n]]
    extras = [n for n in OPTIONAL_DAEMONS if running[n]]
    restarted = []
    for name in expected:
        for pid in running[name]:
            up = proc_uptime(pid)
            if up is not None and up < args.min_uptime:
                restarted.append("%s (%s)" % (name, ago(up)))
    stale = stale_pid_files(ctx)
    control = os.path.join(ctx["home"], "bin", "ossec-control")
    f = Findings()
    if missing:
        f.add(CRIT, "Not running: %s." % ", ".join(missing),
              "Restart OSSEC (%s restart) and check logs/ossec.log for why they stopped." % control)
    if restarted:
        f.add(WARN, "Recently restarted: %s." % ", ".join(restarted),
              "If this keeps happening a daemon is crashing - check logs/ossec.log.")
    if stale:
        f.add(WARN, "Leftover PID files for processes that no longer exist: %s." % ", ".join(stale),
              "Usually left by a crash or unclean stop; safe to delete once you've confirmed "
              "those daemons are really stopped.")
    summary = "%d of %d required daemons running" % (len(expected) - len(missing), len(expected))
    if extras:
        summary += ", plus %s" % ", ".join(extras)
    return result("daemons", f.status, summary, f.issues, f.advice, expected=expected,
                  missing=missing, pids={n: p for n, p in running.items() if p},
                  stale_pid_files=stale)


def check_queue(ctx):
    path = os.path.join(ctx["home"], "queue", "ossec", "queue")
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return result("queue", CRIT, "The event queue socket %s is missing" % path,
                      advice=["It's created when OSSEC starts - restart OSSEC."])
    except OSError as exc:
        return result("queue", UNKNOWN, "Can't check %s (%s)" % (path, exc.strerror),
                      advice=["Re-run with sudo."])
    if not stat.S_ISSOCK(st.st_mode):
        return result("queue", CRIT, "%s exists but isn't a socket" % path,
                      advice=["Stop OSSEC, remove the file, and start OSSEC again."])
    return result("queue", OK, "Event queue socket is present", path=path)


def check_client_keys(ctx):
    path = os.path.join(ctx["home"], "etc", "client.keys")
    try:
        st = os.stat(path)
        with open(path, "r", errors="replace") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        if ctx["mode"] == "agent":
            return result("client_keys", CRIT, "No client.keys - this agent was never registered",
                          advice=["Register it with the server (manage_agents or ossec-authd), "
                                  "then restart the agent."])
        return result("client_keys", OK, "No agents registered yet")
    except OSError as exc:
        return result("client_keys", UNKNOWN, "Can't read %s (%s)" % (path, exc.strerror),
                      advice=["Re-run with sudo."])

    # "ID NAME IP KEY"; removed agents have names starting with '#' (OSSEC) or '!' (forks)
    entries = [l.split() for l in lines]
    entries = [e for e in entries if len(e) >= 4 and not e[1].startswith(("#", "!"))]
    dupes = sorted(n for n, c in collections.Counter(e[1] for e in entries).items() if c > 1)
    f = Findings()
    if ctx["mode"] == "agent":
        if not entries:
            summary = "client.keys has no valid entry"
            f.add(CRIT, "This agent isn't registered.",
                  "Register it with the server (manage_agents or ossec-authd), then restart the agent.")
        else:
            summary = "Registered as %s (ID %s)" % (entries[0][1], entries[0][0])
            if len(entries) > 1:
                f.add(WARN, "It has %d entries; an agent should have exactly one." % len(entries),
                      "Keep only the entry the server knows about.")
    else:
        summary = "%s registered" % plural(len(entries), "agent")
    if dupes:
        f.add(WARN, "Duplicate agent names: %s." % ", ".join(dupes[:10]),
              "Remove the stale entries with manage_agents on the server.")
    if st.st_mode & 0o004:
        f.add(WARN, "client.keys is world-readable (mode %o), which exposes the agent keys."
              % (st.st_mode & 0o777), "Remove world read access: chmod o-r %s" % path)
    return result("client_keys", f.status, summary, f.issues, f.advice, entries=len(entries),
                  duplicates=dupes, mode="%o" % (st.st_mode & 0o777))


def check_agents(ctx, args):
    tool = os.path.join(ctx["home"], "bin", "agent_control")
    if not os.path.exists(tool):
        return result("agents", UNKNOWN, "%s not found" % tool)
    rc, out, err = run([tool, "-l"], timeout=60)
    if rc is None or (rc != 0 and "ID:" not in out):
        return result("agents", UNKNOWN, "agent_control -l failed (%s)"
                      % (last_line(err) or "exit code %s" % rc))
    buckets = {"active": [], "disconnected": [], "never connected": [], "other": []}
    for line in out.splitlines():
        m = re.search(r"ID:\s*(\d+),\s*Name:\s*(.*?),\s*IP:\s*(.*?),\s*(.+?)\s*$", line)
        if not m or m.group(1) == "000":                 # 000 is the server itself
            continue
        state = m.group(4).lower()
        key = ("never connected" if "never" in state else
               "disconnected" if "disconnected" in state else
               "active" if "active" in state else "other")
        buckets[key].append(m.group(2))
    total = sum(len(v) for v in buckets.values())
    if not total:
        return result("agents", OK, "No agents registered")
    disc, never = sorted(buckets["disconnected"]), sorted(buckets["never connected"])
    pct = len(disc) * 100.0 / total

    def names(items):
        return ", ".join(items[:10]) + (" and %d more" % (len(items) - 10) if len(items) > 10 else "")

    f, notes = Findings(), []
    if disc and (pct >= args.agent_crit_pct or (args.agent_warn and len(disc) >= args.agent_warn)):
        f.add(CRIT if pct >= args.agent_crit_pct else WARN,
              "%s disconnected (%.0f%%): %s." % (plural(len(disc), "agent"), pct, names(disc)),
              "Check those hosts are up, the OSSEC agent is running on them, and %s to this "
              "server isn't blocked." % agent_port(ctx))
    if never:
        notes.append("%s never connected (%s) - stale registrations or agents not deployed yet."
                     % (plural(len(never), "agent"), names(never)))
    summary = "%s: %d active, %d disconnected, %d never connected" % (
        plural(total, "agent"), len(buckets["active"]), len(disc), len(never))
    return result("agents", f.status, summary, f.issues, f.advice, notes, total=total,
                  disconnected_pct=round(pct, 1),
                  **{k.replace(" ", "_"): sorted(v) for k, v in buckets.items()})


def listening_ports(proto):
    """Ports with a listening TCP socket / bound UDP socket, from /proc/net (v4 and v6)."""
    want_state = "0A" if proto == "tcp" else "07"    # TCP_LISTEN / unconnected UDP
    ports = set()
    for path in ("/proc/net/%s" % proto, "/proc/net/%s6" % proto):
        for line in (read_text(path) or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) > 3 and parts[3] == want_state:
                ports.add(int(parts[1].rsplit(":", 1)[1], 16))
    return ports


def check_listener(ctx):
    listeners = ctx["listeners"] or [{"connection": "secure", "port": 1514, "protocol": "udp"}]
    f, up = Findings(), []
    for l in listeners:
        protos = [p.strip() for p in l["protocol"].split(",") if p.strip() in ("tcp", "udp")] or ["udp"]
        purpose = "agents" if l["connection"] == "secure" else l["connection"]
        for proto in protos:
            label = "%s/%d (%s)" % (proto, l["port"], purpose)
            if l["port"] in listening_ports(proto):
                up.append(label)
            else:
                f.add(CRIT if l["connection"] == "secure" else WARN,
                      "Nothing is listening on %s." % label,
                      "ossec-remoted should be listening - restart OSSEC and check logs/ossec.log "
                      "for bind errors.")
    summary = "Listening on " + ", ".join(up) if up else "None of the configured ports are open"
    return result("listener", f.status, summary, f.issues, f.advice, listening=up)


def check_connection(ctx):
    lines = ctx["log_lines"]
    if lines is None:
        return result("connection", UNKNOWN, "Can't read ossec.log", advice=["Re-run with sudo."])
    servers = ", ".join(ctx["servers"]) or "the server (not found in ossec.conf)"
    last = None
    for line in lines:
        if AGENT_UP_RE.search(line):
            last = ("up", line)
        elif AGENT_DOWN_RE.search(line):
            last = ("down", line)
    if last is None:
        return result("connection", OK, "No connection problems logged since ossec.log was "
                      "rotated (server: %s)" % servers, servers=ctx["servers"])
    when = parse_log_time(last[1])
    age = (datetime.now() - when).total_seconds() if when else None
    when_txt = ago(age) if age is not None else "at an unknown time"
    if last[0] == "up":
        return result("connection", OK, "Connected to %s (last connected %s)" % (servers, when_txt),
                      last_event=last[1])
    m = LOG_LINE_RE.match(last[1])
    event = (m.group(3) if m else last[1])[:160]
    if age is not None and age < 300:
        return result("connection", WARN, "Not connected to %s" % servers,
                      ["Lost contact %s: %s" % (when_txt, event)],
                      ["Brief drops happen - re-check in a few minutes."], last_event=last[1])
    return result("connection", CRIT, "Not connected to %s" % servers,
                  ["The last connection event was %s: %s" % (when_txt, event)],
                  ["Check the server is up, that UDP 1514 (or your configured port) from this "
                   "host to the server isn't blocked, and that this agent's key matches the "
                   "server's client.keys."],
                  last_event=last[1])


def check_alerts(ctx, args):
    path = os.path.join(ctx["home"], "logs", "alerts", "alerts.log")
    try:
        age = time.time() - os.path.getmtime(path)
    except FileNotFoundError:
        return result("alerts", WARN, "%s doesn't exist" % path,
                      advice=["It's created when the first alert fires - check ossec-analysisd "
                              "is running."])
    except OSError as exc:
        return result("alerts", UNKNOWN, "Can't check %s (%s)" % (path, exc.strerror),
                      advice=["Re-run with sudo."])
    f = Findings()
    if args.alert_max_age and age > args.alert_max_age * 3600:
        f.add(WARN, "No new alerts for %s." % fmt_duration(age),
              "Check ossec-analysisd is running and agents are sending events. If this manager "
              "is genuinely quiet, raise --alert-max-age.")
    return result("alerts", f.status, "Last alert written %s" % ago(age), f.issues, f.advice,
                  path=path, age_seconds=int(age))


def check_ossec_log(ctx, args):
    lines = ctx["log_lines"]
    if lines is None:
        return result("ossec_log", UNKNOWN, "Can't read ossec.log", advice=["Re-run with sudo."])
    cutoff = datetime.now() - timedelta(hours=args.log_window)
    counts = {"CRITICAL": 0, "ERROR": 0, "WARN": 0}
    grouped = {}        # normalised message -> [count, latest example]
    issues = collections.Counter()
    for line in lines:
        m = LOG_LINE_RE.match(line)
        when = parse_log_time(line)
        if not m or not when or when < cutoff:
            continue
        daemon, message = m.group(2).split("(")[0], m.group(3)
        lvl = LEVEL_RE.match(message)
        level = lvl.group(1).upper() if lvl else ""
        level = "WARN" if level.startswith("WARN") else level
        if level in counts:
            counts[level] += 1
        for i, (pattern, _, _) in enumerate(KNOWN_ISSUES):
            if pattern.search(message):
                issues[i] += 1
        if level in ("CRITICAL", "ERROR"):
            key = "%s: %s" % (daemon, re.sub(r"\d+", "N", message)[:200])
            entry = grouped.setdefault(key, [0, ""])
            entry[0] += 1
            entry[1] = "%s: %s" % (daemon, message)

    window = plural(args.log_window, "hour")
    f = Findings()
    if counts["CRITICAL"]:
        f.add(CRIT, "%s logged in the last %s - a daemon may have failed."
              % (plural(counts["CRITICAL"], "critical error"), window),
              "Read the lines below in logs/ossec.log and fix the cause, then restart OSSEC.")
    if args.log_error_warn and counts["ERROR"] >= args.log_error_warn:
        f.add(WARN, "%s logged in the last %s." % (plural(counts["ERROR"], "error"), window))
        if any("could not open file" in k.lower() for k in grouped):
            f.advice.append("'Could not open file' errors mean a <localfile> entry points at a log "
                            "that doesn't exist - fix or remove it, or raise --log-error-warn.")
        else:
            f.advice.append("Check logs/ossec.log around those times for context.")
    for i, n in sorted(issues.items()):
        _, meaning, fix = KNOWN_ISSUES[i]
        f.add(WARN, "%s (seen %s)." % (meaning, "once" if n == 1 else plural(n, "time")), fix)
    top = sorted(grouped.values(), key=lambda e: -e[0])[:3]
    examples = ["(%dx) %s" % (count, text[:220]) for count, text in top]
    summary = "In the last %s: %d critical, %s, %s" % (
        window, counts["CRITICAL"], plural(counts["ERROR"], "error"), plural(counts["WARN"], "warning"))
    return result("ossec_log", f.status, summary, f.issues, f.advice,
                  examples=examples if f.status != OK else (), counts=counts,
                  top_errors=[{"count": c, "latest": t} for c, t in top])


def check_resources(ctx, args):
    owners = {}
    for name in expected_daemons(ctx) + OPTIONAL_DAEMONS:
        for pid in find_processes(name):
            owners[pid] = name
    mem = meminfo()
    total_kb = mem.get("MemTotal", 0) or 1
    avail_pct = mem.get("MemAvailable", mem.get("MemFree", 0)) * 100.0 / total_kb
    if not owners:
        return result("resources", SKIP, "No OSSEC daemons are running to measure")

    def sample():
        ticks = {}
        for pid in owners:
            ticks.update(thread_cpu_ticks(pid))
        return time.monotonic(), ticks

    t0, s0 = sample()
    time.sleep(max(args.interval, 0.5))
    t1, s1 = sample()
    elapsed = max(t1 - t0, 0.001)
    cpu = collections.Counter()
    hottest = (0.0, None)
    for key, ticks in s1.items():
        if key in s0:
            pct = (ticks - s0[key]) / CLK_TCK / elapsed * 100.0
            cpu[owners[key[0]]] += pct
            if pct > hottest[0]:
                hottest = (pct, owners[key[0]])
    rss = collections.Counter()
    for pid, name in owners.items():
        rss[name] += proc_status(pid).get("VmRSS", 0)

    f = Findings()
    busiest = cpu.most_common(1)[0] if cpu else ("n/a", 0.0)
    if hottest[0] >= args.cpu_warn:
        f.add(WARN, "%s is maxed out at %.0f%% CPU on one thread, so events will back up."
              % (hottest[1], hottest[0]),
              "Find the noisy log sources or expensive rules driving the load, or spread agents "
              "over more managers.")
    if avail_pct < args.min_mem_avail:
        f.add(WARN, "Only %.0f%% of system memory is available." % avail_pct,
              "Find what else is using memory on this host (e.g. with top).")
    summary = "Busiest daemon is %s at %.0f%% CPU; OSSEC uses %s RAM; the system has %.0f%% " \
              "memory available" % (busiest[0], busiest[1], fmt_bytes(sum(rss.values()) * 1024),
                                    avail_pct)
    return result("resources", f.status, summary, f.issues, f.advice,
                  cpu_pct={k: round(v, 1) for k, v in cpu.items()},
                  rss_kb=dict(rss), mem_available_pct=round(avail_pct, 1))


def check_config_test(ctx, args):
    home = ctx["home"]
    passed, failed = [], []
    for name in expected_daemons(ctx):
        binary = os.path.join(home, "bin", name)
        if not os.path.exists(binary):
            continue
        rc, out, err = run([binary, "-t"], timeout=args.validate_timeout)
        if rc == 0:
            passed.append(name)
        else:
            text = out + "\n" + err
            errors = [l.strip() for l in text.splitlines() if re.search(r"error|critical", l, re.I)]
            reason = errors[-1] if errors else last_line(text) or "exit code %s" % rc
            failed.append(reason if reason.startswith(name) else "%s: %s" % (name, reason))
    verify = os.path.join(home, "bin", "verify-agent-conf")
    shared = os.path.join(home, "etc", "shared", "agent.conf")
    if ctx["mode"] == "server" and os.path.exists(verify) and os.path.exists(shared):
        rc, out, err = run([verify], timeout=args.validate_timeout)
        text = out + "\n" + err
        if rc != 0 or re.search(r"\bERROR\b", text):
            failed.append("agent.conf: %s" % last_line(text))
        else:
            passed.append("agent.conf")
    if not passed and not failed:
        return result("config_test", UNKNOWN, "No daemon binaries found to test")
    if failed:
        return result("config_test", CRIT, "Config test failed for %s"
                      % plural(len(failed), "component"), failed,
                      ["Fix these before the next restart - a daemon won't start with a broken "
                       "config."], passed=passed, failed=failed)
    return result("config_test", OK, "Config tests passed for %s" % plural(len(passed), "component"),
                  passed=passed)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def safe(name, fn, *fn_args):
    """Run one check; a bug or surprise in one check must not hide the others."""
    try:
        res = fn(*fn_args)
    except Exception as exc:  # noqa: BLE001
        res = result(name, UNKNOWN, "This check crashed (%s: %s)" % (type(exc).__name__, exc),
                     advice=["This is a bug in the script; the other checks still ran."])
    return res if isinstance(res, list) else [res]


def render_human(results, overall, host, args):
    unicode_ok = "utf" in (getattr(sys.stdout, "encoding", "") or "").lower()
    sym = SYMBOLS if unicode_ok else ASCII_SYMBOLS
    arrow, bullet, sep = ("\u2192", "\u2022", " \u00b7 ") if unicode_ok else ("->", "*", " | ")
    use_color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    width = max(60, min(shutil.get_terminal_size((100, 24)).columns, 110))

    def paint(code, text):
        if not use_color or not code:
            return text
        return "\n".join("\033[%sm%s\033[0m" % (code, line) for line in text.split("\n"))

    def wrap(text, first, rest=None):
        return textwrap.fill(text, width=width, initial_indent=first,
                             subsequent_indent=first if rest is None else rest,
                             break_long_words=False, break_on_hyphens=False)

    def show_details(r, indent):
        if args.verbose:
            for key, value in r["details"].items():
                print(paint("2", wrap("%s: %s" % (key.replace("_", " "), value), indent, indent + "  ")))

    counts = {s: sum(r["status"] == s for r in results) for s in (CRIT, WARN, UNKNOWN)}
    problems = sorted((r for r in results if r["status"] in (CRIT, WARN, UNKNOWN)),
                      key=lambda r: -RANK[r["status"]])
    healthy = [r for r in results if r["status"] == OK]
    skipped = [r for r in results if r["status"] == SKIP]
    tally = []
    if counts[CRIT]:
        tally.append("%d critical" % counts[CRIT])
    if counts[WARN]:
        tally.append(plural(counts[WARN], "warning"))
    if counts[UNKNOWN]:
        tally.append("%d couldn't be checked" % counts[UNKNOWN])
    if not tally:
        tally.append("%s passed" % plural(len(healthy), "check"))

    print(paint("1", "%s health check%s%s%s%s" % (PRODUCT, sep, host, sep,
                                                  datetime.now().strftime("%a %d %b %Y, %H:%M"))))
    print()
    print("%s %s - %s" % (paint(COLORS[overall], sym[overall]),
                          paint("1;" + COLORS[overall], HEADLINES[overall]), ", ".join(tally)))

    if problems:
        print()
        print(paint("1", "Needs attention"))
        for i, r in enumerate(problems):
            if i:
                print()
            print("  %s %s" % (paint(COLORS[r["status"]], sym[r["status"]]), paint("1", r["title"])))
            lines = r["issues"] or [r["summary"]]
            mark = bullet + " " if len(lines) > 1 else ""
            for line in lines:
                print(wrap(mark + line, "    ", "    " + " " * len(mark)))
            if r["issues"]:
                print(paint("2", wrap(r["summary"], "    ")))
            for note in r["notes"]:
                print(paint("2", wrap("Note: " + note, "    ")))
            if r["examples"]:
                print(paint("2", "    Most frequent:"))
                for example in r["examples"]:
                    print(paint("2", wrap(example, "      ", "        ")))
            for tip in r["advice"]:
                print(paint("36", wrap("%s %s" % (arrow, tip), "    ", "    " + " " * (len(arrow) + 1))))
            show_details(r, "    ")

    for heading, group, dim in (("Healthy", healthy, False), ("Not checked", skipped, True)):
        if not group:
            continue
        print()
        print(paint("1", heading))
        title_width = min(max(len(r["title"]) for r in group), 26)
        for r in group:
            prefix = "  %s %s  " % (sym[r["status"]], r["title"].ljust(title_width))
            text = wrap(r["summary"], prefix, " " * len(prefix))
            if dim:
                text = paint("2", text)
            else:
                text = text.replace(sym[r["status"]], paint(COLORS[r["status"]], sym[r["status"]]), 1)
            print(text)
            for note in r["notes"]:
                print(paint("2", wrap("Note: " + note, " " * len(prefix))))
            show_details(r, " " * len(prefix))


def render_compact(results, overall, host):
    counts = {s: sum(r["status"] == s for r in results) for s in (CRIT, WARN, UNKNOWN)}
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print("%s %s - %d critical, %d warning, %d unknown on %s at %s" % (
        PRODUCT.upper(), overall, counts[CRIT], counts[WARN], counts[UNKNOWN], host, stamp))
    width = max(len(r["check"]) for r in results)
    for r in results:
        print("  %-8s  %-*s  %s" % (r["status"], width, r["check"], r["message"]))


def report(results, args):
    overall = max((r["status"] for r in results), key=lambda s: RANK[s], default=OK)
    overall = OK if overall == SKIP else overall
    host = socket.gethostname()
    if args.json:
        print(json.dumps({"product": PRODUCT.lower(), "host": host,
                          "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
                          "overall": overall, "checks": results},
                         default=str, separators=(",", ":")))
    elif args.compact:
        render_compact(results, overall, host)
    else:
        render_human(results, overall, host, args)
    return EXIT_CODES[overall]


def parse_args():
    p = argparse.ArgumentParser(description="Health checks for a Linux OSSEC HIDS install.")
    g = p.add_argument_group("install")
    g.add_argument("--ossec-dir", help="install directory (default: from /etc/ossec-init.conf, else /var/ossec)")
    g.add_argument("--mode", choices=sorted(CORE_DAEMONS), help="install type (default: auto-detect)")

    t = p.add_argument_group("thresholds")
    t.add_argument("--interval", type=float, default=3.0,
                   help="seconds to sample daemon CPU (default %(default)s)")
    t.add_argument("--min-uptime", type=int, default=600,
                   help="warn if a daemon restarted within N seconds (default %(default)s)")
    t.add_argument("--agent-warn", type=int, default=1,
                   help="warn at N or more disconnected agents, 0 disables (default %(default)s)")
    t.add_argument("--agent-crit-pct", type=float, default=20,
                   help="critical when N%% or more agents are disconnected (default %(default)s)")
    t.add_argument("--alert-max-age", type=int, default=24,
                   help="warn if alerts.log unchanged for N hours, 0 disables (default %(default)s)")
    t.add_argument("--log-window", type=int, default=24,
                   help="hours of ossec.log to scan (default %(default)s)")
    t.add_argument("--log-error-warn", type=int, default=1,
                   help="warn at N or more ERROR lines in the window, 0 disables (default %(default)s)")
    t.add_argument("--log-bytes", type=int, default=8 * 1024 * 1024,
                   help="read at most this many bytes from the end of ossec.log (default %(default)s)")
    t.add_argument("--cpu-warn", type=float, default=95,
                   help="warn if any daemon thread exceeds N%% CPU (default %(default)s)")
    t.add_argument("--min-mem-avail", type=float, default=10,
                   help="warn if system MemAvailable below N%% (default %(default)s)")
    t.add_argument("--disk-warn", type=float, default=80, help="disk/inode %% warning (default %(default)s)")
    t.add_argument("--disk-crit", type=float, default=90, help="disk/inode %% critical (default %(default)s)")

    o = p.add_argument_group("output and options")
    o.add_argument("--validate-config", action="store_true",
                   help="also run each daemon's -t config test and verify-agent-conf")
    o.add_argument("--validate-timeout", type=int, default=120, help="seconds (default %(default)s)")
    fmt = o.add_mutually_exclusive_group()
    fmt.add_argument("--compact", action="store_true",
                     help="one line per check, Nagios-style (for monitoring systems and cron mail)")
    fmt.add_argument("--json", action="store_true", help="print one JSON line instead of text")
    o.add_argument("-v", "--verbose", action="store_true", help="show the raw details for each check")
    o.add_argument("--no-color", action="store_true", help="disable colours (NO_COLOR is honoured too)")
    return p.parse_args()


def main():
    args = parse_args()
    if not sys.platform.startswith("linux"):
        print("This script reads /proc and only runs on Linux.", file=sys.stderr)
        return 3
    ctx = discover(args)
    results = []
    results += safe("privileges", check_privileges)
    results += safe("install", check_install, ctx)
    if ctx["mode"] and os.path.isdir(ctx["home"]):
        mode = ctx["mode"]
        results += safe("daemons", check_daemons, ctx, args)
        results += safe("queue", check_queue, ctx)
        if mode != "local":
            results += safe("client_keys", check_client_keys, ctx)
        if mode == "server":
            results += safe("agents", check_agents, ctx, args)
            results += safe("listener", check_listener, ctx)
        if mode == "agent":
            results += safe("connection", check_connection, ctx)
        else:
            results += safe("alerts", check_alerts, ctx, args)
        results += safe("ossec_log", check_ossec_log, ctx, args)
        results += safe("resources", check_resources, ctx, args)
        results += safe("disk", check_disk, ctx["home"], args.disk_warn, args.disk_crit,
                        "Clean up old alerts and archives under logs/, and check the retention job.")
        if args.validate_config:
            results += safe("config_test", check_config_test, ctx, args)
    return report(results, args)


if __name__ == "__main__":
    sys.exit(main())
