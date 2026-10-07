"""Shared helpers: command running, tool detection, flag matching, job state."""
import os
import re
import shutil
import subprocess
import threading
import time
import uuid

# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------
_tool_cache = {}


def have(tool):
    """Return True if an external binary is on PATH (cached)."""
    if tool not in _tool_cache:
        _tool_cache[tool] = shutil.which(tool) is not None
    return _tool_cache[tool]


def run(cmd, timeout=None, cwd=None, input_bytes=None):
    """Run a command. Returns (returncode, stdout, stderr) as text.

    Never raises on non-zero exit; a missing binary returns (-1, '', msg).
    timeout=None means run to completion (user asked: always run everything).
    """
    try:
        p = subprocess.run(
            cmd,
            cwd=cwd,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        out = p.stdout.decode("utf-8", "replace") if p.stdout else ""
        err = p.stderr.decode("utf-8", "replace") if p.stderr else ""
        return p.returncode, out, err
    except FileNotFoundError:
        return -1, "", f"binary not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", f"timeout after {timeout}s: {' '.join(cmd)}"
    except Exception as e:  # noqa: BLE001
        return -3, "", f"error running {cmd[0]}: {e}"


# ---------------------------------------------------------------------------
# Flag handling
# ---------------------------------------------------------------------------
# Generic fallbacks always tried in addition to the user's format.
GENERIC_FLAG_PATTERNS = [
    r"[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,256}\}",
    r"flag\{[^}\r\n]{1,256}\}",
    r"FLAG\{[^}\r\n]{1,256}\}",
    r"CTF\{[^}\r\n]{1,256}\}",
]


def build_flag_regexes(flag_format):
    """Turn a user-supplied flag format into a list of compiled regexes.

    Accepts:
      - A full regex (contains '{' or regex metachars)  -> used as-is
      - A simple prefix like 'XploitX'                   -> PREFIX\\{...\\}
      - Empty                                            -> generics only
    Returns (primary_regexes, generic_regexes).
    """
    primary = []
    fmt = (flag_format or "").strip()
    if fmt:
        looks_like_regex = any(c in fmt for c in ".*+?[]()|\\") or "{" in fmt
        if "{" in fmt and "}" in fmt:
            # Treat as a template/regex. Escape if it has no regex metachars
            # other than the braces, so 'XploitX{...}' becomes a real pattern.
            if re.search(r"\.\*|\[|\]|\\|\+|\?|\(|\)|\|", fmt):
                pat = fmt
            else:
                # Replace an inner '...' or placeholder with a greedy-ish class
                body = re.sub(r"\{[^}]*\}", r"{BODY}", fmt)
                pat = re.escape(body).replace(re.escape("{BODY}"),
                                              r"\{[^}\r\n]{1,256}\}")
            primary.append(pat)
        elif looks_like_regex:
            primary.append(fmt)
        else:
            primary.append(re.escape(fmt) + r"\{[^}\r\n]{1,256}\}")

    compiled_primary = []
    for p in primary:
        try:
            compiled_primary.append(re.compile(p))
        except re.error:
            compiled_primary.append(re.compile(re.escape(p)))

    compiled_generic = [re.compile(p) for p in GENERIC_FLAG_PATTERNS]
    return compiled_primary, compiled_generic


def find_flags(text, primary, generic):
    """Return (confirmed, likely) lists of distinct flag strings found in text."""
    if not text:
        return [], []
    confirmed, likely = [], []
    seen = set()
    for rx in primary:
        for m in rx.findall(text):
            s = m if isinstance(m, str) else m[0]
            if s not in seen:
                seen.add(s)
                confirmed.append(s)
    for rx in generic:
        for m in rx.findall(text):
            s = m if isinstance(m, str) else m[0]
            if s not in seen:
                seen.add(s)
                likely.append(s)
    return confirmed, likely


# ---------------------------------------------------------------------------
# Job state (in-memory)
# ---------------------------------------------------------------------------
class Job:
    """Holds the live log and findings for one analysis run."""

    def __init__(self, job_id, filename, flag_format):
        self.id = job_id
        self.filename = filename
        self.flag_format = flag_format
        self.logs = []            # list of {t, level, msg}
        self.flags = []           # confirmed flag strings
        self.likely = []          # likely flag strings (with source note)
        self.done = False
        self.started = time.time()
        self._lock = threading.RLock()
        self.primary, self.generic = build_flag_regexes(flag_format)

    def log(self, msg, level="info"):
        with self._lock:
            self.logs.append({"t": round(time.time() - self.started, 1),
                              "level": level, "msg": msg})

    def section(self, title):
        self.log("", "blank")
        self.log("=" * 60, "rule")
        self.log(title, "section")
        self.log("=" * 60, "rule")

    def scan(self, text, source):
        """Scan a blob of text for flags and record any hits."""
        confirmed, likely = find_flags(text, self.primary, self.generic)
        with self._lock:
            for f in confirmed:
                if f not in self.flags:
                    self.flags.append(f)
                    self.log(f"[+] FLAG FOUND ({source}): {f}", "flag")
            for f in likely:
                tag = f"{f}  ⟵ {source}"
                if not any(f == x.split("  ⟵")[0] for x in self.likely):
                    self.likely.append(tag)
                    self.log(f"[?] likely flag ({source}): {f}", "likely")

    def snapshot(self, since=0):
        with self._lock:
            return {
                "logs": self.logs[since:],
                "total": len(self.logs),
                "flags": list(self.flags),
                "likely": list(self.likely),
                "done": self.done,
            }


JOBS = {}


def new_job(filename, flag_format):
    jid = uuid.uuid4().hex[:12]
    JOBS[jid] = Job(jid, filename, flag_format)
    return JOBS[jid]


def get_job(jid):
    return JOBS.get(jid)
