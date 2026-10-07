"""PCAP: tshark field extraction, HTTP object export, DNS reassembly, USB HID."""
import os

from . import util

# USB HID keyboard scancode -> character (no modifier / shift).
HID = {
    0x04: ("a", "A"), 0x05: ("b", "B"), 0x06: ("c", "C"), 0x07: ("d", "D"),
    0x08: ("e", "E"), 0x09: ("f", "F"), 0x0a: ("g", "G"), 0x0b: ("h", "H"),
    0x0c: ("i", "I"), 0x0d: ("j", "J"), 0x0e: ("k", "K"), 0x0f: ("l", "L"),
    0x10: ("m", "M"), 0x11: ("n", "N"), 0x12: ("o", "O"), 0x13: ("p", "P"),
    0x14: ("q", "Q"), 0x15: ("r", "R"), 0x16: ("s", "S"), 0x17: ("t", "T"),
    0x18: ("u", "U"), 0x19: ("v", "V"), 0x1a: ("w", "W"), 0x1b: ("x", "X"),
    0x1c: ("y", "Y"), 0x1d: ("z", "Z"),
    0x1e: ("1", "!"), 0x1f: ("2", "@"), 0x20: ("3", "#"), 0x21: ("4", "$"),
    0x22: ("5", "%"), 0x23: ("6", "^"), 0x24: ("7", "&"), 0x25: ("8", "*"),
    0x26: ("9", "("), 0x27: ("0", ")"),
    0x28: ("\n", "\n"), 0x2b: ("\t", "\t"), 0x2c: (" ", " "),
    0x2d: ("-", "_"), 0x2e: ("=", "+"), 0x2f: ("[", "{"), 0x30: ("]", "}"),
    0x31: ("\\", "|"), 0x33: (";", ":"), 0x34: ("'", "\""),
    0x36: (",", "<"), 0x37: (".", ">"), 0x38: ("/", "?"), 0x2a: ("[BKSP]", "[BKSP]"),
}


def _tshark(args):
    return util.run(["tshark"] + args)


def _fields(path, job):
    """Pull the fields that usually carry CTF data."""
    extractors = [
        ("HTTP requests", ["-Y", "http.request", "-T", "fields",
                           "-e", "http.host", "-e", "http.request.uri",
                           "-e", "http.request.method"]),
        ("HTTP auth (basic)", ["-Y", "http.authorization", "-T", "fields",
                               "-e", "http.authorization"]),
        ("FTP commands", ["-Y", "ftp.request.command", "-T", "fields",
                          "-e", "ftp.request.command", "-e", "ftp.request.arg"]),
        ("Telnet data", ["-Y", "telnet.data", "-T", "fields",
                         "-e", "telnet.data"]),
        ("POST form data", ["-Y", "urlencoded-form", "-T", "fields",
                            "-e", "urlencoded-form.key",
                            "-e", "urlencoded-form.value"]),
        ("ICMP payloads", ["-Y", "icmp", "-T", "fields", "-e", "data.data"]),
    ]
    for label, extra in extractors:
        rc, out, _ = _tshark(["-r", path] + extra)
        if rc == 0 and out.strip():
            job.log(f"[*] {label}:")
            for line in out.splitlines()[:200]:
                if line.strip():
                    job.log("    " + line)
            job.scan(out, f"pcap:{label}")


def _credentials(path, job):
    rc, out, _ = _tshark(["-r", path, "-z", "credentials", "-q"])
    if rc == 0 and out.strip():
        job.log("[*] tshark credential scan:")
        for line in out.splitlines():
            job.log("    " + line)
        job.scan(out, "pcap:credentials")


def _dns(path, job):
    """DNS exfiltration: concatenate queried subdomain labels in order."""
    rc, out, _ = _tshark(["-r", path, "-Y", "dns.flags.response == 0",
                          "-T", "fields", "-e", "dns.qry.name"])
    if rc == 0 and out.strip():
        names = [l.strip() for l in out.splitlines() if l.strip()]
        job.log(f"[*] {len(names)} DNS queries seen")
        # Common pattern: data is the first label of each query.
        labels = []
        for n in names:
            parts = n.split(".")
            if parts:
                labels.append(parts[0])
        reassembled = "".join(labels)
        job.scan(reassembled, "pcap:dns-reassembled")
        job.scan("\n".join(names), "pcap:dns-names")


def _export_objects(path, job, out_dir):
    for proto in ("http", "smb", "tftp", "ftp-data", "imf"):
        ex_dir = os.path.join(out_dir, f"objects_{proto}")
        os.makedirs(ex_dir, exist_ok=True)
        rc, _, _ = _tshark(["-r", path, f"--export-objects",
                            f"{proto},{ex_dir}", "-q"])
        files = [os.path.join(ex_dir, f) for f in os.listdir(ex_dir)] \
            if os.path.isdir(ex_dir) else []
        if files:
            job.log(f"[+] exported {len(files)} {proto} objects -> {ex_dir}",
                    "good")


def _usb_hid(path, job):
    """Decode USB keyboard capture (usb.capdata) into typed text."""
    rc, out, _ = _tshark(["-r", path, "-Y", "usb.capdata",
                          "-T", "fields", "-e", "usb.capdata"])
    if rc != 0 or not out.strip():
        # Newer field name
        rc, out, _ = _tshark(["-r", path, "-Y", "usbhid.data",
                              "-T", "fields", "-e", "usbhid.data"])
    if rc != 0 or not out.strip():
        return
    typed = []
    for line in out.splitlines():
        hexstr = line.strip().replace(":", "")
        if len(hexstr) < 16:
            continue
        try:
            b = bytes.fromhex(hexstr)
        except ValueError:
            continue
        mod, key = b[0], b[2]
        if key == 0:
            continue
        if key in HID:
            shift = bool(mod & 0x22)
            typed.append(HID[key][1 if shift else 0])
    if typed:
        text = "".join(typed)
        job.log(f"[+] USB keyboard HID decoded: {text}", "good")
        job.scan(text, "pcap:usb-hid")


def run(path, job, out_dir):
    job.section("6. PCAP / NETWORK ANALYSIS")
    if not util.have("tshark"):
        job.log("[!] tshark not installed (apt install tshark) — PCAP "
                "analysis skipped", "warn")
        return
    rc, out, _ = _tshark(["-r", path, "-q", "-z", "io,phs"])
    if rc == 0:
        job.log("[*] protocol hierarchy:")
        for line in out.splitlines():
            if line.strip():
                job.log("    " + line)
    _credentials(path, job)
    _fields(path, job)
    _dns(path, job)
    _usb_hid(path, job)
    _export_objects(path, job, out_dir)
