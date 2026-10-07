"""Archives & documents: zip cracking (john/fcrackzip), office macros, pdf."""
import os
import zipfile

from . import util

WORDLIST = "/usr/share/wordlists/rockyou.txt"


def _crack_zip(path, job, out_dir):
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return
    encrypted = [zi for zi in z.infolist() if zi.flag_bits & 0x1]
    if not encrypted:
        return
    job.log(f"[*] encrypted zip with {len(encrypted)} protected entries")

    wordlist = WORDLIST if os.path.exists(WORDLIST) else None

    # Prefer fcrackzip, then john, then pure-python.
    if util.have("fcrackzip") and wordlist:
        rc, out, _ = util.run(
            ["fcrackzip", "-D", "-p", wordlist, "-u", path])
        if "PASSWORD FOUND" in out:
            job.log(f"[+] fcrackzip: {out.strip()}", "flag")
            job.scan(out, "zip-crack")
    if util.have("zip2john") and util.have("john") and wordlist:
        h = os.path.join(out_dir, "zip.hash")
        rc, out, _ = util.run(["zip2john", path])
        if out:
            with open(h, "w") as f:
                f.write(out)
            util.run(["john", f"--wordlist={wordlist}", h])
            _, show, _ = util.run(["john", "--show", h])
            job.log(f"[*] john --show:\n{show}")
            job.scan(show, "zip-john")

    # Pure-python fallback with a small list + rockyou.
    pwset = ["password", "flag", "ctf", "123456", "admin", "secret", "infected"]
    if wordlist:
        try:
            with open(wordlist, encoding="latin-1") as f:
                pwset += [w.strip() for w in f]
        except Exception:
            pass
    for pw in pwset:
        try:
            z.extractall(path=os.path.join(out_dir, "zip_cracked"),
                         pwd=pw.encode("latin-1", "ignore"))
            job.log(f"[+] zip password is '{pw}'", "flag")
            cdir = os.path.join(out_dir, "zip_cracked")
            for root, _, files in os.walk(cdir):
                for fn in files:
                    fp = os.path.join(root, fn)
                    with open(fp, "rb") as f:
                        job.scan(f.read().decode("latin-1", "replace"),
                                 f"zip:{fn}")
            return
        except Exception:
            continue


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
        _crack_zip(path, job, out_dir)
    _office(path, job)
    _pdf(path, job)
