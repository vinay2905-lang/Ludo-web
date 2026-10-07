# Forensics Autosolver — bakes every external tool into the image so it runs
# identically on Render, Kali, and Windows (Docker Desktop).
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# --- system forensics tooling ------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      file binutils \
      binwalk foremost \
      steghide \
      exiftool libimage-exiftool-perl \
      tshark \
      fcrackzip john \
      poppler-utils \
      libmagic1 libzbar0 \
      ruby ruby-dev build-essential \
      ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

# zsteg + exif gems (image stego)
RUN gem install --no-document zsteg || true

# tshark must run without a TTY prompt and as non-root capture
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" \
      | debconf-set-selections

# --- python deps -------------------------------------------------------------
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt \
    && pip install volatility3 oletools matplotlib

# --- rockyou wordlist (for zip/steghide cracking) ----------------------------
RUN mkdir -p /usr/share/wordlists \
    && (wget -q -O /usr/share/wordlists/rockyou.txt \
        https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
        || echo "rockyou download skipped (offline); add it manually")

COPY . .

ENV PORT=8000
EXPOSE 8000

# gunicorn with a long timeout because "run everything" jobs are slow.
RUN pip install gunicorn
CMD ["sh", "-c", "gunicorn -w 2 -k gthread --threads 8 -t 0 -b 0.0.0.0:${PORT} app:app"]
