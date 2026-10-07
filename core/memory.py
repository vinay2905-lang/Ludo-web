"""Memory dumps: run a fixed sweep of Volatility 3 plugins and scan output."""
import os
import re

from . import util

# Plugins run blindly; vol3 auto-detects the profile.
PLUGINS = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.filescan",
    "windows.dumpfiles",
    "windows.netscan",
    "windows.hashdump",
    "windows.clipboard",
    "windows.consoles",
    "windows.envars",
    "windows.registry.hivelist",
]

LINUX_PLUGINS = [
    "linux.pslist",
    "linux.bash",
    "linux.psaux",
]


def _vol_cmd():
    if util.have("vol"):
        return ["vol"]
    if util.have("vol.py"):
        return ["vol.py"]
    if util.have("volatility3"):
        return ["volatility3"]
    # python module form
    return None


def _looks_like_memory(path):
    ext = os.path.splitext(path)[1].lower()
    return ext in (".raw", ".mem", ".vmem", ".dmp", ".lime", ".img") or \
        os.path.getsize(path) > 50_000_000


def run(path, job, out_dir):
    if not _looks_like_memory(path):
        return
    job.section("8. MEMORY DUMP (Volatility 3)")
    base = _vol_cmd()
    if base is None:
        rc, _, _ = util.run(["python3", "-c", "import volatility3"])
        if rc == 0:
            base = ["python3", "-m", "volatility3"]
        else:
            job.log("[!] Volatility 3 not installed (pip install "
                    "volatility3) — memory analysis skipped", "warn")
            return

    plugins = PLUGINS + LINUX_PLUGINS
    for plug in plugins:
        args = base + ["-f", path, plug]
        if plug == "windows.dumpfiles":
            dd = os.path.join(out_dir, "vol_dumpfiles")
            os.makedirs(dd, exist_ok=True)
            args = base + ["-o", dd, "-f", path, plug]
        job.log(f"[*] volatility: {plug}")
        rc, out, err = util.run(args)
        if rc == 0 and out.strip():
            # Keep log readable; scan full output for flags.
            for line in out.splitlines()[:150]:
                job.log("    " + line)
            job.scan(out, f"vol:{plug}")
        elif err and "Unsatisfied requirement" not in err:
            snippet = err.strip().splitlines()[-1] if err.strip() else ""
            if snippet:
                job.log(f"    ({snippet})", "warn")
