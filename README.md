# Forensics Autosolver

A scripted (no AI, no LLM) automation tool for CTF forensics challenges.
Upload a file, give your flag format, watch the live log, and read the
confirmed / likely flags it finds.

It chains the standard forensics tools into one recursive pipeline and
greps everything for your flag format.

## Categories covered

| # | Category | What it runs |
|---|----------|--------------|
| 1 | File identification | magic-byte sniff, `file`, extension-mismatch, PNG header repair |
| 2 | Strings & encodings | pure-python + binutils `strings`, base64/32, hex, rot-N, url, reverse, **single-byte XOR brute force** |
| 3 | Embedded files | `binwalk -e`, `foremost`, a built-in signature carver, recursive unzip |
| 4 | Image stego | `exiftool`, `zsteg -a`, `steghide` (empty + rockyou), python LSB + per-channel bit planes, **PNG CRC height brute force**, QR decode |
| 5 | Audio | spectrogram render, DTMF decode, WAV LSB |
| 6 | PCAP | `tshark` protocol hierarchy + credentials, HTTP/FTP/telnet/POST fields, **DNS exfil reassembly**, **USB-HID keyboard decode**, object export |
| 7 | Archives & docs | zip crack (`fcrackzip`/`zip2john`+`john`/python, rockyou), `olevba` macros, PDF text/raw |
| 8 | Memory dumps | Volatility 3 plugin sweep (pslist, cmdline, filescan, hashdump, clipboard, consoles, linux.bash, …) |

Every extracted/carved/decoded artifact is **fed back through the whole
pipeline** (up to 3 levels deep), so nested challenges unwrap automatically.

## Run it

### Docker (recommended — matches Render exactly)
```bash
docker build -t forensics .
docker run -p 8000:8000 forensics
# open http://localhost:8000
```

### Local Python (Kali: tools already installed)
```bash
pip install -r requirements.txt
pip install volatility3 oletools matplotlib
python app.py          # http://localhost:8000
```
On Kali, install anything missing:
```bash
sudo apt install binwalk foremost steghide exiftool tshark fcrackzip john poppler-utils
sudo gem install zsteg
```

### Windows host
Use **Docker Desktop** and the Docker command above — native Windows can't
run several of these tools. The UI opens in your Windows browser at
`http://localhost:8000`.

## Deploy to Render

1. Push this repo to GitHub.
2. Render dashboard → **New → Blueprint** → select the repo (`render.yaml`
   is detected).
3. Use the **Starter** plan — the free tier's 512 MB RAM will OOM on
   Volatility and large PCAPs.
4. Render generates an `ACCESS_TOKEN`; copy it from the service's
   Environment tab and paste it into the UI's token field.

## Flag format box
- `XploitX`        → becomes `XploitX\{…\}`
- `XploitX{...}`   → becomes a real pattern matching that shape
- a full regex     → used as-is
- blank            → matches any `word{…}`, plus `flag{}`, `CTF{}`, `FLAG{}`

## Notes / limits
- "Run everything" means rockyou brute-forcing runs to completion — a run
  can take minutes. The log streams live so you see hits immediately.
- SSTV isn't auto-decoded; the spectrogram + saved audio let you finish it
  in `qsstv`.
- Nothing here uses AI — it's deterministic scripts and standard CLI tools,
  so it's fine for AI-banned CTFs. (You are still responsible for following
  your competition's rules.)
