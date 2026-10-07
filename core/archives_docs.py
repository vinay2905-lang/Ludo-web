"""Archives & documents: zip cracking (john/fcrackzip), office macros, pdf."""
import os
import zipfile

from . import util

WORDLIST = "/usr/share/wordlists/rockyou.txt"


def _zip_try_python(z, pwset, job, out_dir):
    """Try each password via python's zipfile; scan extracted contents."""
    for pw in pwset:
        try:
            cdir = os.path.join(out_dir, "zip_cracked")
            z.extractall(path=cdir, pwd=pw.encode("latin-1", "ignore"))
            job.log(f"[+] zip password is '{pw}'", "flag")
            for root, _, files in os.walk(cdir):
                for fn in files:
                    with open(os.path.join(root, fn), "rb") as f:
                        job.scan(f.read().decode("latin-1", "replace"),
                                 f"zip:{fn}")
            return True
        except Exception:
            continue
    return False


def _crack_zip_fast(path, job, out_dir):
    """Fast phase: small built-in password list only."""
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return
    encrypted = [zi for zi in z.infolist() if zi.flag_bits & 0x1]
    if not encrypted:
        return
    job.log(f"[*] encrypted zip with {len(encrypted)} protected entries "
            "(trying quick list; use deep scan for rockyou)")
    small = ["password", "flag", "ctf", "123456", "admin", "secret",
             "infected", "letmein", "root", "toor"]
    _zip_try_python(z, small, job, out_dir)


def crack_zip_deep(path, job, out_dir):
    """Deep phase: fcrackzip / zip2john+john / python, all with rockyou."""
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return
    if not any(zi.flag_bits & 0x1 for zi in z.infolist()):
        return
    wordlist = WORDLIST if os.path.exists(WORDLIST) else None
    if not wordlist:
        job.log("[*] zip deep: rockyou not found, skipping", "warn")
        return
    job.log(f"[*] zip deep: rockyou brute force on {os.path.basename(path)}")

    if util.have("fcrackzip"):
        rc, out, _ = util.run(["fcrackzip", "-D", "-p", wordlist, "-u", path])
        if "PASSWORD FOUND" in out:
            job.log(f"[+] fcrackzip: {out.strip()}", "flag")
            job.scan(out, "zip-crack")
    if util.have("zip2john") and util.have("john"):
        h = os.path.join(out_dir, "zip.hash")
        rc, out, _ = util.run(["zip2john", path])
        if out:
            with open(h, "w") as f:
                f.write(out)
            util.run(["john", f"--wordlist={wordlist}", h])
            _, show, _ = util.run(["john", "--show", h])
            job.log(f"[*] john --show:\n{show}")
            job.scan(show, "zip-john")

    try:
        with open(wordlist, encoding="latin-1") as f:
            _zip_try_python(z, (w.strip() for w in f), job, out_dir)
    except Exception:  # noqa: BLE001
        pass


def _office(path, job):
    if util.have("olevba"):
        rc, out, _ = util.run(["olevba", path])
        if rc == 0 and out.strip():
            job.log("[*] olevba (macros):")
            for line in out.splitlines()[:300]:
                job.log("    " + line)
            job.scan(out, "olevba")
    # docx/xlsx are zips of XML — scan their text parts.
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    if name.endswith((".xml", ".rels", ".txt")):
                        job.scan(z.read(name).decode("utf-8", "replace"),
                                 f"office:{name}")
        except Exception:
            pass


def _pdf(path, job):
    with open(path, "rb") as f:
        head = f.read(5)
    if head != b"%PDF":
        return
    if util.have("pdftotext"):
        rc, out, _ = util.run(["pdftotext", path, "-"])
        if rc == 0:
            job.scan(out, "pdf-text")
    if util.have("pdf-parser"):
        rc, out, _ = util.run(["pdf-parser", "-a", path])
        if rc == 0:
            job.scan(out, "pdf-parser")
    # Raw scan catches flags hidden in white text / streams / comments.
    with open(path, "rb") as f:
        job.scan(f.read().decode("latin-1", "replace"), "pdf-raw")


def run(path, job, out_dir):
    job.section("7. ARCHIVES & DOCUMENTS")
    if zipfile.is_zipfile(path):
        _crack_zip_fast(path, job, out_dir)
    _office(path, job)
    _pdf(path, job)
