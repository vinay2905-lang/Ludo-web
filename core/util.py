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
# Generic fallbacks tried when the user gives no flag format. Deliberately
# strict so random binary like "xx{|}" / "a7{<}" does NOT match: the prefix
# must start with a letter and the body must start alphanumeric and contain a
# run of at least 4 word-ish characters.
# Body is restricted to characters real flags actually use (word chars plus a
# little safe punctuation) and may not contain spaces, quotes, backslashes or
# braces — which is what makes random binary spans like "a7{ <|\"}" stop
# matching. A truly exotic flag format should be entered explicitly instead.
_BODY = r"[A-Za-z0-9_][A-Za-z0-9_!?.@#$%+\-]{3,120}"
GENERIC_FLAG_PATTERNS = [
    r"[A-Za-z][A-Za-z0-9_]{1,19}\{" + _BODY + r"\}",
    r"flag\{" + _BODY + r"\}",
    r"FLAG\{" + _BODY + r"\}",
    r"CTF\{" + _BODY + r"\}",
    r"pico(?:CTF)?\{" + _BODY + r"\}",
]

# Cap how many distinct "likely" (generic) hits we keep, so a noisy file
# cannot flood the UI with thousands of near-random matches.
MAX_LIKELY = 60


def flag_score(flag):
    """Heuristic: how much a generic match looks like a real CTF flag.

    Real flags tend to have a longer body, contain underscores/digits, and be
    mostly word characters rather than random punctuation.
    """
    body = flag[flag.find("{") + 1:flag.rfind("}")]
    if not body:
        return 0.0
    import re as _re
    L = len(body)
    word = len(_re.findall(r"[A-Za-z0-9_]", body))
    ratio = word / L
    score = 20 * ratio                # mostly-word bodies look like flags
    score += 8 if "_" in body else 0  # underscores are a strong signal
    if L < 4:
        score -= 10
    if L > 60:                        # real flags are rarely very long;
        score -= (L - 60) * 0.5       # random spans tend to be
    return score


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


def find_flags(text, primary, generic, primary_only=False):
    """Return (confirmed, likely) lists of distinct flag strings found in text.

    primary_only=True skips the loose generic patterns entirely. Decoded and
    XOR'd data MUST use this: matching a generic flag shape against decoded
    random bytes is essentially always a false positive.
    """
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
    if not primary_only:
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
        self._likely_capped = False
        self.done = False
        self.started = time.time()
        self._lock = threading.RLock()
        self.primary, self.generic = build_flag_regexes(flag_format)
        # phase tracking for fast-first + manual deep scan
        self.phase = "fast"        # fast | deep
        self.deep_available = False  # set True when the fast phase finishes
        self.deep_started = False
        self.saved_path = None       # the uploaded file on disk
        self.work_dir = None         # per-job working directory
        # files discovered during the fast phase (host + extracted), each as
        # (path, out_dir); the deep phase re-targets all of them.
        self.discovered = []

    def add_discovered(self, path, out_dir):
        with self._lock:
            if not any(p == path for p, _ in self.discovered):
                self.discovered.append((path, out_dir))

    def log(self, msg, level="info"):
        with self._lock:
            self.logs.append({"t": round(time.time() - self.started, 1),
                              "level": level, "msg": msg})

    def section(self, title):
        self.log("", "blank")
        self.log("=" * 60, "rule")
        self.log(title, "section")
        self.log("=" * 60, "rule")

    def scan(self, text, source, primary_only=False):
        """Scan a blob of text for flags and record any hits.

        primary_only=True (used for decoded/XOR'd data) only reports matches
        of the user's flag format, never the loose generic patterns.
        """
        confirmed, likely = find_flags(text, self.primary, self.generic,
                                       primary_only=primary_only)
        with self._lock:
            for f in confirmed:
                if f not in self.flags:
                    self.flags.append(f)
                    self.log(f"[+] FLAG FOUND ({source}): {f}", "flag")
            for f in likely:
                if any(f == x.split("  ⟵")[0] for x in self.likely):
                    continue
                if len(self.likely) < MAX_LIKELY:
                    self.likely.append(f"{f}  ⟵ {source}")
                    self.log(f"[?] likely flag ({source}): {f}", "likely")
                else:
                    # Keep only the best-looking candidates once full: if this
                    # one scores higher than the current weakest, swap it in.
                    scored = [(flag_score(x.split("  ⟵")[0]), i)
                              for i, x in enumerate(self.likely)]
                    worst_score, worst_i = min(scored)
                    if flag_score(f) > worst_score:
                        self.likely[worst_i] = f"{f}  ⟵ {source}"
                        self.log(f"[?] likely flag ({source}): {f}", "likely")
                    if not self._likely_capped:
                        self._likely_capped = True
                        self.log(f"[*] likely list full ({MAX_LIKELY}); keeping"
                                 " best-scoring — enter a flag format to filter",
                                 "warn")

    def snapshot(self, since=0):
        with self._lock:
            return {
                "logs": self.logs[since:],
                "total": len(self.logs),
                "flags": list(self.flags),
                "likely": sorted(
                    self.likely,
                    key=lambda x: flag_score(x.split("  ⟵")[0]),
                    reverse=True),
                "done": self.done,
                "phase": self.phase,
                "deep_available": self.deep_available,
                "deep_started": self.deep_started,
            }


JOBS = {}


def new_job(filename, flag_format):
    jid = uuid.uuid4().hex[:12]
    JOBS[jid] = Job(jid, filename, flag_format)
    return JOBS[jid]


def get_job(jid):
    return JOBS.get(jid)
