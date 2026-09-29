#!/usr/bin/env python3
"""
snort_healthcheck.py - health checks for a Linux Snort sensor (Snort 2.9.x or 3.x).

Checks
  permissions   warns when not run as root (some checks need it)
  process       snort is running, expected instance count, recent restarts
  service       systemd unit(s): active, enabled at boot, oneshot updater results
  version       binary version; flags a binary replaced under a running process
  config        config present/readable; notes edits made after snort started
  interface     per sniffing interface: link, promiscuous mode, traffic, NIC drops
  daq_drops     Snort's own drop rate from perfmonitor (2.x) / perf_monitor CSV (3.x)
  rules         rule files present, active rule count, age of the last rule update
  alerts        alert output still being written
  disk          space and inodes on the log partition
  resources     Snort RSS/swap, per-thread CPU saturation, system memory and load
  require:*     companion processes named with --require-process (e.g. barnyard2)
  config_test   full config validation with `snort -T` (only with --validate-config)

Output
  default       readable report: problems first, each with a suggested next step,
                then a one-line-per-check list of what's healthy
  --compact     one line per check; the first line is the overall status (Nagios-style)
  --json        one JSON object on one line (SIEM scripted inputs, jq)

Stdlib only, Python 3.6+. Exit codes follow the Nagios plugin convention
(0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN) in every output mode.

Examples
  sudo ./snort_healthcheck.py
  sudo ./snort_healthcheck.py -i eth1 --interval 10 --validate-config -v
  sudo ./snort_healthcheck.py --require-process barnyard2 --compact
"""

import argparse
import functools
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import time
from datetime import datetime

OK, WARN, CRIT, UNKNOWN, SKIP = "OK", "WARNING", "CRITICAL", "UNKNOWN", "SKIPPED"
RANK = {SKIP: -1, OK: 0, UNKNOWN: 1, WARN: 2, CRIT: 3}
EXIT_CODES = {SKIP: 0, OK: 0, WARN: 1, CRIT: 2, UNKNOWN: 3}
COLORS = {OK: "32", WARN: "33", CRIT: "31", UNKNOWN: "35", SKIP: "2"}
SYMBOLS = {OK: "\u2714", WARN: "\u26a0", CRIT: "\u2716", UNKNOWN: "?", SKIP: "\u2013"}
ASCII_SYMBOLS = {OK: "+", WARN: "!", CRIT: "x", UNKNOWN: "?", SKIP: "-"}
HEADLINES = {OK: "All good", WARN: "Needs attention", CRIT: "Problems found",
             UNKNOWN: "Some checks couldn't run"}
CLK_TCK = float(os.sysconf("SC_CLK_TCK"))

PRODUCT = "Snort"
TITLES = {
    "privileges": "Permissions", "process": "Snort process", "service": "Systemd service",
    "version": "Snort version", "config": "Config file", "interface": "Sniffing interface",
    "daq_drops": "Drops inside Snort", "rules": "Rules", "alerts": "Alert output",
    "disk": "Disk space", "resources": "CPU and memory", "require": "Required processes",
    "config_test": "Config validation",
}

SNORT2_CONFIGS = ["/etc/snort/snort.conf", "/usr/local/etc/snort/snort.conf"]
SNORT3_CONFIGS = ["/usr/local/etc/snort/snort.lua", "/etc/snort/snort.lua",
                  "/opt/snort/etc/snort/snort.lua"]
RULE_DIRS = ["/etc/snort/rules", "/usr/local/etc/rules", "/usr/local/etc/snort/rules"]
SNORT_BINARIES = ["/usr/local/bin/snort", "/usr/sbin/snort", "/usr/bin/snort",
                  "/opt/snort/bin/snort"]
RULE_ACTIONS = {"alert", "log", "pass", "drop", "reject", "sdrop", "block",
                "rewrite", "react", "activate", "dynamic"}
ALERT_FILE_RE = re.compile(r"alert|^snort\.log|^snort\.u2|unified2|merged\.log|\.pcap$", re.I)
IFACE_COUNTERS = ("rx_packets", "rx_bytes", "rx_dropped", "rx_missed_errors",
                  "rx_fifo_errors", "rx_errors")
IFF_UP, IFF_PROMISC = 0x1, 0x100


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #

def title_for(check):
    base, _, arg = check.partition(":")
    if arg:
        return {"interface": "Interface %s", "service": "Service %s",
                "require": "Process %s"}.get(base, base + " %s") % arg
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


def tail_lines(path, max_bytes=65536):
    """Last lines of a file without reading all of it."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - max_bytes))
        data = fh.read()
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[1:] if size > max_bytes and lines else lines  # first line may be partial


def mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


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
    """Parse /proc/<pid>/stat or /proc/<pid>/task/<tid>/stat."""
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
    """kB-valued fields (VmRSS, VmSwap, ...) from /proc/<pid>/status."""
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


def iso(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def existing_parent(path):
    path = os.path.abspath(path)
    while not os.path.exists(path) and path != "/":
        path = os.path.dirname(path)
    return path


def walk_files(top, max_depth=2):
    """Files under `top`, descending at most max_depth-1 directory levels."""
    base = top.rstrip("/").count(os.sep)
    for root, dirs, files in os.walk(top):
        if root.rstrip("/").count(os.sep) - base >= max_depth - 1:
            dirs[:] = []
        for name in files:
            yield os.path.join(root, name)


def check_disk(path, warn_pct, crit_pct, cleanup_advice):
    target = existing_parent(path)
    usage = shutil.disk_usage(target)
    denom = usage.used + usage.free
    space_pct = usage.used * 100.0 / denom if denom else 0.0
    vfs = os.statvfs(target)
    inode_pct = (vfs.f_files - vfs.f_ffree) * 100.0 / vfs.f_files if vfs.f_files else 0.0
    f = Findings()
    for pct, issue in ((space_pct, "The disk is %.0f%% full." % space_pct),
                       (inode_pct, "%.0f%% of inodes are used - many small files (pcaps, rotated "
                                   "logs) can exhaust these before space runs out." % inode_pct)):
        if pct >= warn_pct:
            f.add(CRIT if pct >= crit_pct else WARN, issue, cleanup_advice)
    summary = "%.0f%% used, %s free, %.0f%% of inodes used (%s)" % (
        space_pct, fmt_bytes(usage.free), inode_pct, target)
    return result("disk", f.status, summary, f.issues, f.advice, path=target,
                  space_used_pct=round(space_pct, 1), free_bytes=usage.free,
                  inodes_used_pct=round(inode_pct, 1))


# --------------------------------------------------------------------------- #
# Discovery: work out what this sensor looks like
# --------------------------------------------------------------------------- #

def parse_snort_argv(pid, argv):
    """Pull -i (interfaces), -c (config) and -l (log dir) out of a snort command line."""
    found = {"interfaces": [], "config": None, "log_dir": None}
    flags = {"-i": "interfaces", "--interface": "interfaces", "-c": "config", "-l": "log_dir"}
    i = 1
    while i < len(argv):
        arg, key, value = argv[i], None, None
        if arg in flags and i + 1 < len(argv):
            key, value = flags[arg], argv[i + 1]
            i += 1
        elif "=" in arg and arg.split("=", 1)[0] in flags:
            flag, value = arg.split("=", 1)
            key = flags[flag]
        elif arg[:2] in flags and len(arg) > 2:          # attached form, e.g. -ieth1
            key, value = flags[arg[:2]], arg[2:]
        i += 1
        if key == "interfaces":
            # "eth0:eth1" is an inline pair; Snort 3 also accepts "eth0 eth1"
            found["interfaces"] += [p for p in re.split(r"[:,\s]+", value) if p]
        elif key:
            if not os.path.isabs(value):                 # relative to snort's cwd
                try:
                    value = os.path.join(os.readlink("/proc/%d/cwd" % pid), value)
                except OSError:
                    pass
            found[key] = value
    return found


def interfaces_from_config(path):
    text = read_text(path) or ""
    m = re.search(r"^\s*config\s+interface\s*:\s*(\S+)", text, re.M)         # Snort 2
    if m:
        return [p for p in re.split(r"[:,]", m.group(1)) if p]
    m = re.search(r"inputs\s*=\s*\{([^}]*)\}", text)                           # Snort 3 daq
    if m:
        return re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
    return []


def discover(args):
    ctx = {"pids": [], "binary": None, "binary_replaced": False, "version": None,
           "major": None, "config": args.config, "interfaces": list(args.interface or []),
           "log_dir": args.log_dir, "rule_dirs": []}

    for name in args.process_name:
        ctx["pids"] += find_processes(name)
    ctx["pids"] = sorted(set(ctx["pids"]))

    from_argv = {"interfaces": [], "config": None, "log_dir": None}
    for pid in ctx["pids"]:
        found = parse_snort_argv(pid, proc_argv(pid))
        from_argv["interfaces"] += found["interfaces"]
        from_argv["config"] = from_argv["config"] or found["config"]
        from_argv["log_dir"] = from_argv["log_dir"] or found["log_dir"]

    # Prefer the binary the running process was started from.
    for pid in ctx["pids"]:
        try:
            exe = os.readlink("/proc/%d/exe" % pid)
        except OSError:
            continue
        if exe.endswith(" (deleted)"):
            ctx["binary_replaced"] = True
            exe = exe[:-len(" (deleted)")]
        ctx["binary"] = exe
        break
    if ctx["binary"] and not os.access(ctx["binary"], os.X_OK):
        ctx["binary"] = None
    if not ctx["binary"]:
        for cand in [shutil.which("snort")] + SNORT_BINARIES:
            if cand and os.access(cand, os.X_OK):
                ctx["binary"] = cand
                break

    if ctx["binary"]:
        _, out, err = run([ctx["binary"], "-V"], timeout=30)
        m = re.search(r"Version\s+(\d+(?:\.\d+)+)", out + err)
        if m:
            ctx["version"] = m.group(1)
            ctx["major"] = int(m.group(1).split(".")[0])

    if not ctx["config"]:
        ctx["config"] = from_argv["config"]
    if not ctx["config"]:
        order = SNORT3_CONFIGS + SNORT2_CONFIGS if ctx["major"] == 3 else SNORT2_CONFIGS + SNORT3_CONFIGS
        ctx["config"] = next((c for c in order if os.path.isfile(c)), None)

    if not ctx["interfaces"]:
        ctx["interfaces"] = from_argv["interfaces"] or (
            interfaces_from_config(ctx["config"]) if ctx["config"] else [])
    ctx["interfaces"] = list(dict.fromkeys(ctx["interfaces"]))

    ctx["log_dir"] = ctx["log_dir"] or from_argv["log_dir"] or "/var/log/snort"

    dirs = list(args.rules_dir or [])
    if not dirs:
        dirs = list(RULE_DIRS)
        if ctx["config"]:
            dirs.append(os.path.join(os.path.dirname(ctx["config"]), "rules"))
    ctx["rule_dirs"] = [d for d in dict.fromkeys(os.path.realpath(d) for d in dirs)
                        if os.path.isdir(d)]
    return ctx


def latest_start(ctx):
    """Epoch time of the most recent snort (re)start, or None."""
    ups = [u for u in (proc_uptime(pid) for pid in ctx["pids"]) if u is not None]
    return time.time() - min(ups) if ups else None


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

def check_privileges():
    if os.geteuid() == 0:
        return []
    return result("privileges", WARN, "Not running as root, so some checks may be incomplete",
                  advice=["Re-run with sudo for complete results."])


def check_process(ctx, args):
    pids = ctx["pids"]
    if not pids:
        return result("process", CRIT, "Snort isn't running (no process named %s)"
                      % " or ".join(args.process_name),
                      advice=["Start Snort, then find out why it stopped: journalctl -u <snort unit> "
                              "or the Snort log."])
    uptimes = {pid: proc_uptime(pid) for pid in pids}
    known = [u for u in uptimes.values() if u is not None]
    f = Findings()
    summary = "%s running (PID %s)" % (plural(len(pids), "process", "processes"),
                                       ", ".join(map(str, pids)))
    if known:
        summary += ", %s %s" % ("newest up" if len(pids) > 1 else "up", fmt_duration(min(known)))
        if min(known) < args.min_uptime:
            f.add(WARN, "Snort restarted %s." % ago(min(known)),
                  "If this keeps happening Snort is probably crashing - check journalctl or "
                  "/var/log/messages for errors.")
    if args.expect_procs and len(pids) < args.expect_procs:
        f.add(CRIT, "Expected at least %d Snort processes but found %d."
              % (args.expect_procs, len(pids)),
              "One instance has died - find the interface that has no Snort attached.")
    return result("process", f.status, summary, f.issues, f.advice, pids=pids,
                  uptime_seconds={str(p): int(u) for p, u in uptimes.items() if u is not None})


def systemd_units(pattern):
    names = set()
    for cmd in (["systemctl", "list-units", "--all", "--type=service", "--no-legend", "--no-pager"],
                ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]):
        _, out, _ = run(cmd)
        for line in out.splitlines():
            parts = line.replace("\u25cf", " ").split()
            if parts and pattern.match(parts[0]) and "@." not in parts[0]:  # skip templates
                names.add(parts[0])
    return sorted(names)


def check_service(ctx, args):
    if not shutil.which("systemctl"):
        return result("service", SKIP, "systemctl isn't available on this host")
    units = args.unit or systemd_units(re.compile(r"^snort[\w@.:-]*\.service$"))
    if not units:
        return result("service", SKIP, "No snort systemd unit found (started by an init script "
                      "or supervisor?)")
    results = []
    for unit in units:
        props = {}
        _, text, _ = run(["systemctl", "show", unit, "--no-pager"] + [
            "--property=%s" % p for p in ("LoadState", "ActiveState", "SubState", "Type",
                                          "Result", "UnitFileState", "NRestarts")])
        for line in text.splitlines():
            key, _, value = line.partition("=")
            props[key] = value
        name = "service:%s" % unit
        journal = "journalctl -u %s -n 50" % unit
        if props.get("LoadState") == "not-found":
            results.append(result(name, CRIT if args.unit else SKIP, "Unit not found",
                                  advice=["List Snort units with: systemctl list-units --all 'snort*'"]))
            continue
        active, sub = props.get("ActiveState", "unknown"), props.get("SubState", "?")
        enabled = props.get("UnitFileState", "")
        f, notes, skipped = Findings(), [], False
        if props.get("Type") == "oneshot":            # e.g. a pulledpork rule-update unit
            last = props.get("Result", "") or "n/a"
            summary = "Oneshot unit (e.g. a rule updater), last run: %s" % last
            if last not in ("success", "n/a"):
                f.add(WARN, "Its last run failed (%s)." % last, "See why with: %s" % journal)
        elif active == "active":
            summary = "Running" + (", starts at boot" if enabled == "enabled" else "")
            if enabled == "disabled":
                f.add(WARN, "It's disabled, so it won't start after a reboot.",
                      "Enable it with: systemctl enable %s" % unit)
        elif active == "failed":
            summary = "State: failed (%s)" % sub
            f.add(CRIT, "systemd reports the unit as failed.", "See why with: %s" % journal)
        elif enabled in ("disabled", "masked") and not args.unit:
            summary, skipped = "Inactive and %s, so not in use" % enabled, True
        else:
            summary = "State: %s (%s)" % (active, sub)
            f.add(CRIT, "The unit isn't running.",
                  "Start it with: systemctl start %s - then check %s if it doesn't stay up." % (unit, journal))
        restarts = props.get("NRestarts", "")
        if restarts.isdigit() and int(restarts) > 0:
            notes.append("systemd has restarted it %s since it was loaded."
                         % ("once" if int(restarts) == 1 else plural(int(restarts), "time")))
        results.append(result(name, SKIP if skipped else f.status, summary, f.issues, f.advice,
                              notes, **props))
    return results


def check_version(ctx):
    if not ctx["binary"]:
        return result("version", UNKNOWN, "Couldn't find the snort binary",
                      advice=["Make sure snort is on the PATH, or check the install."])
    if not ctx["version"]:
        return result("version", UNKNOWN, "Couldn't read the version from `%s -V`" % ctx["binary"],
                      binary=ctx["binary"])
    if ctx["binary_replaced"]:
        return result("version", WARN, "Snort %s on disk (%s)" % (ctx["version"], ctx["binary"]),
                      ["The binary was upgraded after Snort started, so the running process is "
                       "still the old version."], ["Restart Snort to run the new version."],
                      version=ctx["version"], binary=ctx["binary"])
    return result("version", OK, "Snort %s (%s)" % (ctx["version"], ctx["binary"]),
                  version=ctx["version"], binary=ctx["binary"])


def check_config(ctx):
    conf = ctx["config"]
    if not conf:
        return result("config", CRIT, "No Snort config found",
                      advice=["Pass the path with --config."])
    if not os.path.isfile(conf):
        return result("config", CRIT, "%s doesn't exist" % conf,
                      advice=["Check the -c path Snort was started with, or pass --config."])
    if not os.access(conf, os.R_OK):
        return result("config", UNKNOWN, "%s isn't readable" % conf,
                      advice=["Re-run with sudo."])
    modified = mtime(conf)
    notes = []
    started = latest_start(ctx)
    if started and modified > started:
        notes.append("It was edited after Snort last started - make sure Snort was reloaded.")
    return result("config", OK, "%s, last edited %s" % (conf, ago(time.time() - modified)),
                  notes=notes, path=conf, modified=iso(modified))


def iface_counters(iface):
    base = "/sys/class/net/%s/statistics/" % iface
    out = {}
    for key in IFACE_COUNTERS:
        value = (read_text(base + key) or "").strip()
        out[key] = int(value) if value.isdigit() else 0
    return out


def take_sample(ctx):
    sample = {"t": time.monotonic(), "iface": {}, "threads": {}}
    for iface in ctx["interfaces"]:
        sample["iface"][iface] = iface_counters(iface)
    for pid in ctx["pids"]:
        sample["threads"].update(thread_cpu_ticks(pid))
    return sample


def check_interfaces(ctx, s0, s1, args):
    if not ctx["interfaces"]:
        return result("interface", SKIP, "No sniffing interface identified (NFQ or pcap mode?) "
                      "- pass -i to check one")
    elapsed = max(s1["t"] - s0["t"], 0.001)
    results = []
    for iface in ctx["interfaces"]:
        name = "interface:%s" % iface
        base = "/sys/class/net/%s" % iface
        if not os.path.isdir(base):
            results.append(result(name, CRIT, "The interface doesn't exist",
                                  advice=["Check the name with `ip link`, or pass the right one with -i."]))
            continue
        operstate = (read_text(base + "/operstate") or "unknown").strip()
        try:
            flags = int((read_text(base + "/flags") or "0").strip(), 16)
        except ValueError:
            flags = 0
        c0, c1 = s0["iface"][iface], s1["iface"][iface]
        delta = {k: max(c1[k] - c0[k], 0) for k in IFACE_COUNTERS}
        # missed/fifo = NIC ring overflow. rx_dropped can be inflated on SPAN ports by
        # older kernels (frames with no protocol handler), hence --ignore-rx-dropped.
        nic_drops = delta["rx_missed_errors"] + delta["rx_fifo_errors"]
        drops = nic_drops + (0 if args.ignore_rx_dropped else delta["rx_dropped"])
        seen = delta["rx_packets"] + drops
        drop_pct = drops * 100.0 / seen if seen else 0.0
        pps = delta["rx_packets"] / elapsed
        mbps = delta["rx_bytes"] * 8 / elapsed / 1e6

        f = Findings()
        if not flags & IFF_UP or operstate in ("down", "lowerlayerdown", "notpresent"):
            f.add(CRIT, "The link is down (%s)." % operstate, "Check the cable and the switch port.")
        if args.min_pps and pps < args.min_pps:
            f.add(CRIT, "No packets arrived during the %.0f-second sample." % elapsed,
                  "Check the SPAN/TAP feed: switch port mirroring, the cable, and that Snort is "
                  "listening on the right interface.")
        if drop_pct >= args.drop_warn:
            limit = args.drop_crit if drop_pct >= args.drop_crit else args.drop_warn
            f.add(CRIT if drop_pct >= args.drop_crit else WARN,
                  "The network card dropped %.2f%% of packets (limit %.1f%%)." % (drop_pct, limit),
                  "The sensor can't keep up at the NIC: raise the RX ring size (ethtool -G), check "
                  "IRQ/CPU affinity, or reduce the load.")
            if delta["rx_dropped"] and not nic_drops:
                f.advice.append("On a SPAN port with an older kernel rx_dropped can be inflated - "
                                "try --ignore-rx-dropped.")
        if not flags & IFF_PROMISC and not args.skip_promisc:
            f.add(WARN, "It isn't in promiscuous mode, so Snort only sees traffic addressed to "
                        "this host.",
                  "The DAQ normally turns this on - check the DAQ settings, or use --skip-promisc "
                  "if it's intentional.")
        link = {"up": "Link up", "down": "Link down",
                "unknown": "Link state unknown"}.get(operstate, "Link %s" % operstate)
        summary = "%s, %s packets/s, %.1f Mbit/s, %.2f%% dropped" % (
            link, "{:,.0f}".format(pps), mbps, drop_pct)
        details = {"operstate": operstate, "promiscuous": bool(flags & IFF_PROMISC),
                   "pps": round(pps, 1), "mbps": round(mbps, 2), "drop_pct": round(drop_pct, 3),
                   "sample_seconds": round(elapsed, 1)}
        details.update(("delta_" + k, v) for k, v in delta.items())
        results.append(result(name, f.status, summary, f.issues, f.advice, **details))
    return results


def find_perfmon_file(ctx, args):
    if args.perfmon_file:
        return args.perfmon_file
    candidates = [os.path.join(ctx["log_dir"], "snort.stats"), "/var/snort/snort.stats",
                  "/var/log/snort/snort.stats"]
    for d in {ctx["log_dir"], "/var/log/snort"}:
        try:
            candidates += [os.path.join(d, n) for n in os.listdir(d)
                           if n.endswith("perf_monitor_base.csv")]
        except OSError:
            pass
    existing = [c for c in candidates if os.path.isfile(c)]
    return max(existing, key=mtime) if existing else None


def read_perfmon(path):
    """(columns, last_row) from a perfmonitor / perf_monitor CSV with a '#' header line."""
    lines = tail_lines(path)
    last_hdr = max((i for i, l in enumerate(lines) if l.startswith("#")), default=None)
    if last_hdr is not None:
        header, data = lines[last_hdr], lines[last_hdr + 1:]
    else:
        with open(path, "rb") as fh:
            first = fh.readline().decode("utf-8", "replace")
        header, data = (first if first.startswith("#") else ""), lines
    cols = [c.strip() for c in header.lstrip("#").split(",")] if header else []
    rows = [l for l in data if l.strip() and not l.startswith("#")]
    row = [c.strip() for c in rows[-1].split(",")] if rows else []
    return cols, row


def check_daq_drops(ctx, args):
    path = find_perfmon_file(ctx, args)
    if not path:
        return result("daq_drops", SKIP, "perfmonitor isn't enabled, so drops inside Snort can't "
                      "be measured (NIC drops are still checked)")
    age = time.time() - mtime(path)
    cols, row = read_perfmon(path)
    index = {c: i for i, c in enumerate(cols)}

    def num(col):
        try:
            return float(row[index[col]])
        except (KeyError, IndexError, ValueError):
            return None

    pct = None
    if "pkt_drop_percent" in index:                                   # Snort 2
        pct = num("pkt_drop_percent")
    elif "daq.received" in index and "daq.dropped" in index:          # Snort 3
        received, dropped = num("daq.received"), num("daq.dropped")
        if received is not None and dropped is not None:
            pct = dropped * 100.0 / (received + dropped) if received + dropped else 0.0
    elif not cols and len(row) > 1:                                   # headerless Snort 2 file
        try:
            pct = float(row[1])
        except ValueError:
            pct = None

    if pct is None:
        return result("daq_drops", UNKNOWN, "Couldn't find drop counters in %s" % path, path=path)
    f = Findings()
    if pct >= args.drop_warn:
        f.add(CRIT if pct >= args.drop_crit else WARN,
              "Snort itself is dropping %.2f%% of packets." % pct,
              "Snort is overloaded: trim or tune the ruleset, add packet threads or instances, "
              "or give it more CPU.")
    if age > args.perfmon_max_age:
        f.add(WARN, "The stats file hasn't been updated for %s." % fmt_duration(age),
              "Check perfmonitor is still enabled and Snort is actually processing packets.")
    summary = "%.2f%% of packets dropped by Snort (%s, updated %s)" % (
        pct, os.path.basename(path), ago(age))
    return result("daq_drops", f.status, summary, f.issues, f.advice, path=path,
                  drop_pct=round(pct, 3), age_seconds=int(age))


def count_rules(path):
    active = disabled = 0
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            text = line.strip()
            if not text:
                continue
            if text.startswith("#"):
                body = text.lstrip("#").strip()
                if body and body.split(None, 1)[0] in RULE_ACTIONS and "(" in body:
                    disabled += 1
            elif text.split(None, 1)[0] in RULE_ACTIONS:
                active += 1
    return active, disabled


def check_rules(ctx, args):
    if not ctx["rule_dirs"]:
        return result("rules", WARN, "No rules directory found",
                      advice=["Pass it with --rules-dir."])
    files = sorted({p for d in ctx["rule_dirs"] for p in walk_files(d) if p.endswith(".rules")})
    if not files:
        return result("rules", CRIT, "No .rules files in %s" % ", ".join(ctx["rule_dirs"]),
                      advice=["Check the rule updater's output, or pass the right --rules-dir."])
    active = disabled = 0
    for path in files:
        a, d = count_rules(path)
        active, disabled = active + a, disabled + d
    newest_path = max(files, key=mtime)
    newest = mtime(newest_path)
    age = time.time() - newest
    f, notes = Findings(), []
    if active == 0:
        f.add(CRIT, "There are no active rules, so Snort can't detect anything.",
              "Check the rule updater's output and the rule include lines in the config.")
    elif args.rules_max_age and age > args.rules_max_age * 86400:
        f.add(WARN, "Rules haven't been updated for %s." % fmt_duration(age),
              "Check that pulledpork (or your rule updater) still runs from cron/systemd and can "
              "reach the rule feed.")
    started = latest_start(ctx)
    if started and newest > started:
        notes.append("Rules changed after Snort last started - make sure Snort reloaded them.")
    summary = "%s active and %s disabled rules in %s, last updated %s" % (
        "{:,}".format(active), "{:,}".format(disabled), plural(len(files), "file"), ago(age))
    return result("rules", f.status, summary, f.issues, f.advice, notes, dirs=ctx["rule_dirs"],
                  files=len(files), active=active, disabled=disabled, newest_file=newest_path,
                  newest_modified=iso(newest))


def check_alerts(ctx, args):
    log_dir = ctx["log_dir"]
    if not os.path.isdir(log_dir):
        return result("alerts", CRIT, "The log directory %s doesn't exist" % log_dir,
                      advice=["Create it, or pass the right one with --log-dir."])
    files = [p for p in walk_files(log_dir) if ALERT_FILE_RE.search(os.path.basename(p))]
    if not files:
        return result("alerts", WARN, "No alert files in %s" % log_dir,
                      advice=["If Snort only alerts to syslog this is expected; otherwise pass "
                              "--log-dir."])
    newest_path = max(files, key=mtime)
    age = time.time() - mtime(newest_path)
    f = Findings()
    if args.alert_max_age and age > args.alert_max_age * 3600:
        f.add(WARN, "No new alerts for %s." % fmt_duration(age),
              "A live sensor usually fires something - check it's seeing traffic and the rules "
              "loaded. If this sensor is genuinely quiet, raise --alert-max-age.")
    summary = "Last alert written %s (%s)" % (ago(age), os.path.relpath(newest_path, log_dir))
    return result("alerts", f.status, summary, f.issues, f.advice, log_dir=log_dir,
                  newest_file=newest_path, age_seconds=int(age))


def check_resources(ctx, s0, s1, args):
    mem = meminfo()
    total_kb = mem.get("MemTotal", 0) or 1
    avail_pct = mem.get("MemAvailable", mem.get("MemFree", 0)) * 100.0 / total_kb
    _, load5, _ = os.getloadavg()
    cpus = os.cpu_count() or 1
    f, parts, details = Findings(), [], {}

    if ctx["pids"]:
        rss_kb = swap_kb = 0
        for pid in ctx["pids"]:
            st = proc_status(pid)
            rss_kb += st.get("VmRSS", 0)
            swap_kb += st.get("VmSwap", 0)
        rss_pct = rss_kb * 100.0 / total_kb
        elapsed = max(s1["t"] - s0["t"], 0.001)
        per_thread = {key: (ticks - s0["threads"][key]) / CLK_TCK / elapsed * 100.0
                      for key, ticks in s1["threads"].items() if key in s0["threads"]}
        total_cpu = sum(per_thread.values())
        part = "Snort uses %s RAM (%.0f%%) and %.0f%% CPU" % (fmt_bytes(rss_kb * 1024), rss_pct, total_cpu)
        details.update(snort_rss_kb=rss_kb, snort_swap_kb=swap_kb, snort_cpu_pct=round(total_cpu, 1))
        if per_thread:
            (pid, tid), hot = max(per_thread.items(), key=lambda kv: kv[1])
            tname = (read_text("/proc/%d/task/%d/comm" % (pid, tid)) or "?").strip()
            part += " (busiest thread %.0f%%)" % hot
            details.update(busiest_thread="%s/%d" % (tname, tid), busiest_thread_pct=round(hot, 1))
            if hot >= args.cpu_warn:
                f.add(WARN, "Snort thread %s/%d is at %.0f%% CPU, so it's saturated and will drop "
                            "packets." % (tname, tid, hot),
                      "Spread the load (more packet threads or instances, CPU pinning) or trim "
                      "the ruleset.")
        parts.append(part)
        if swap_kb:
            f.add(WARN, "%s of Snort's memory is swapped out, which stalls packet processing."
                  % fmt_bytes(swap_kb * 1024), "Add RAM or reduce Snort's memory settings.")
        if rss_pct >= args.mem_warn:
            f.add(WARN, "Snort is using %.0f%% of the machine's RAM." % rss_pct,
                  "Watch whether it keeps growing (a leak), or reduce memory-hungry settings.")

    parts.append("the system has %.0f%% memory available and a load of %.2f on %s"
                 % (avail_pct, load5, plural(cpus, "CPU")))
    details.update(mem_available_pct=round(avail_pct, 1), load5=load5, cpus=cpus)
    if avail_pct < args.min_mem_avail:
        f.add(WARN, "Only %.0f%% of system memory is available." % avail_pct,
              "Find what else is using memory on this sensor (e.g. with top).")
    if load5 > cpus * 2:
        f.add(WARN, "The load average (%.1f) is more than twice the CPU count." % load5,
              "Something is overloading the host - check top.")
    summary = "; ".join(parts)
    return result("resources", f.status, summary[0].upper() + summary[1:], f.issues, f.advice,
                  **details)


def check_required(args):
    results = []
    for name in args.require_process or []:
        pids = find_processes(name)
        if pids:
            results.append(result("require:%s" % name, OK, "Running (PID %s)"
                                  % ", ".join(map(str, pids)), pids=pids))
        else:
            results.append(result("require:%s" % name, CRIT, "%s isn't running" % name,
                                  advice=["Start it - without it, alerts may not reach your "
                                          "database or SIEM."], pids=[]))
    return results


def check_config_test(ctx, args):
    if not ctx["binary"] or not ctx["config"]:
        return result("config_test", UNKNOWN, "Needs both a snort binary and a config to validate")
    if ctx["pids"] and not args.config:
        # Re-use the running command line so -R, --plugin-path, -i etc. match what's live.
        argv = proc_argv(ctx["pids"][0])
        cmd = [ctx["binary"]] + [a for a in argv[1:]
                                 if a not in ("-D", "--daemon", "--create-pidfile")] + ["-T"]
    else:
        cmd = [ctx["binary"], "-T", "-c", ctx["config"]]
    started = time.time()
    rc, out, err = run(cmd, timeout=args.validate_timeout)
    text = out + "\n" + err
    took = time.time() - started
    if rc == 0 and re.search(r"successfully validated", text, re.I):
        m = re.search(r"with (\d+) warnings", text)
        notes = ["Snort reported %s." % plural(int(m.group(1)), "warning")] if m and int(m.group(1)) else []
        return result("config_test", OK, "Config is valid (checked in %s)" % fmt_duration(took),
                      notes=notes, command=" ".join(cmd))
    errors = [l.strip() for l in text.splitlines() if re.search(r"error|fatal", l, re.I)][-3:]
    if not errors:
        errors = [(err.strip().splitlines() or ["exit code %s" % rc])[-1]]
    return result("config_test", CRIT, "snort -T rejected the config", errors,
                  ["Fix this before the next restart - Snort won't start with this config."],
                  command=" ".join(cmd), returncode=rc)


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
    p = argparse.ArgumentParser(description="Health checks for a Linux Snort sensor.")
    g = p.add_argument_group("what to check (auto-detected from the running process by default)")
    g.add_argument("-i", "--interface", action="append", help="sniffing interface (repeatable)")
    g.add_argument("-c", "--config", help="snort.conf or snort.lua")
    g.add_argument("-l", "--log-dir", help="Snort log directory (fallback /var/log/snort)")
    g.add_argument("--rules-dir", action="append", help="directory holding *.rules (repeatable)")
    g.add_argument("--perfmon-file", help="perfmonitor snort.stats / perf_monitor_base.csv")
    g.add_argument("--process-name", action="append", help="process name (default: snort)")
    g.add_argument("--unit", action="append", help="systemd unit(s) to check (default: snort*)")
    g.add_argument("--require-process", action="append", metavar="NAME",
                   help="companion process that must be running, e.g. barnyard2 (repeatable)")
    g.add_argument("--expect-procs", type=int, default=0,
                   help="minimum number of snort processes (multi-instance sensors)")

    t = p.add_argument_group("thresholds")
    t.add_argument("--interval", type=float, default=5.0,
                   help="seconds to sample traffic and CPU (default %(default)s)")
    t.add_argument("--min-uptime", type=int, default=600,
                   help="warn if snort restarted within N seconds (default %(default)s)")
    t.add_argument("--min-pps", type=float, default=1.0,
                   help="critical below N packets/s on an interface, 0 disables (default %(default)s)")
    t.add_argument("--drop-warn", type=float, default=1.0, help="drop %% warning (default %(default)s)")
    t.add_argument("--drop-crit", type=float, default=5.0, help="drop %% critical (default %(default)s)")
    t.add_argument("--ignore-rx-dropped", action="store_true",
                   help="exclude the kernel rx_dropped counter from NIC drop %% (noisy on some SPAN ports)")
    t.add_argument("--skip-promisc", action="store_true", help="don't warn about promiscuous mode")
    t.add_argument("--rules-max-age", type=int, default=7,
                   help="warn if rules older than N days, 0 disables (default %(default)s)")
    t.add_argument("--alert-max-age", type=int, default=24,
                   help="warn if no alert written for N hours, 0 disables (default %(default)s)")
    t.add_argument("--perfmon-max-age", type=int, default=900,
                   help="warn if perfmon stats older than N seconds (default %(default)s)")
    t.add_argument("--disk-warn", type=float, default=80, help="disk/inode %% warning (default %(default)s)")
    t.add_argument("--disk-crit", type=float, default=90, help="disk/inode %% critical (default %(default)s)")
    t.add_argument("--mem-warn", type=float, default=80,
                   help="warn if snort RSS exceeds N%% of RAM (default %(default)s)")
    t.add_argument("--min-mem-avail", type=float, default=10,
                   help="warn if system MemAvailable below N%% (default %(default)s)")
    t.add_argument("--cpu-warn", type=float, default=95,
                   help="warn if any snort thread exceeds N%% CPU (default %(default)s)")

    o = p.add_argument_group("output and options")
    o.add_argument("--validate-config", action="store_true",
                   help="also run `snort -T` (slow on big rulesets; loads a second copy of the rules)")
    o.add_argument("--validate-timeout", type=int, default=300, help="seconds (default %(default)s)")
    fmt = o.add_mutually_exclusive_group()
    fmt.add_argument("--compact", action="store_true",
                     help="one line per check, Nagios-style (for monitoring systems and cron mail)")
    fmt.add_argument("--json", action="store_true", help="print one JSON line instead of text")
    o.add_argument("-v", "--verbose", action="store_true", help="show the raw details for each check")
    o.add_argument("--no-color", action="store_true", help="disable colours (NO_COLOR is honoured too)")
    args = p.parse_args()
    args.process_name = args.process_name or ["snort"]
    return args


def main():
    args = parse_args()
    if not sys.platform.startswith("linux"):
        print("This script reads /proc and /sys and only runs on Linux.", file=sys.stderr)
        return 3
    ctx = discover(args)
    results = []
    results += safe("privileges", check_privileges)
    results += safe("process", check_process, ctx, args)
    results += safe("service", check_service, ctx, args)
    results += safe("version", check_version, ctx)
    results += safe("config", check_config, ctx)
    s0 = take_sample(ctx)
    time.sleep(max(args.interval, 0.5))
    s1 = take_sample(ctx)
    results += safe("interface", check_interfaces, ctx, s0, s1, args)
    results += safe("daq_drops", check_daq_drops, ctx, args)
    results += safe("rules", check_rules, ctx, args)
    results += safe("alerts", check_alerts, ctx, args)
    results += safe("disk", check_disk, ctx["log_dir"], args.disk_warn, args.disk_crit,
                    "Clean up old Snort logs and pcaps, and check that logrotate is running.")
    results += safe("resources", check_resources, ctx, s0, s1, args)
    results += safe("require", check_required, args)
    if args.validate_config:
        results += safe("config_test", check_config_test, ctx, args)
    return report(results, args)


if __name__ == "__main__":
    sys.exit(main())
