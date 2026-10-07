"""Flask web UI for the CTF forensics automation tool.

Routes:
  GET  /                      -> upload UI
  POST /api/analyze           -> accept file + flag format, start a job
  GET  /api/stream/<job_id>   -> Server-Sent Events: live logs + flags
  GET  /api/result/<job_id>   -> JSON snapshot (polling fallback)
  GET  /healthz               -> health check for Render
"""
import json
import os
import tempfile
import threading
import time

from flask import (Flask, Response, jsonify, render_template, request,
                   stream_with_context)

from core import util
from core.pipeline import analyze

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("MAX_UPLOAD_MB", "512")) * 1024 * 1024

# Optional shared-secret gate for the public Render deployment.
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", "")

WORK_ROOT = os.environ.get("WORK_DIR", tempfile.gettempdir())


def _authorized(req):
    if not ACCESS_TOKEN:
        return True
    tok = req.headers.get("X-Access-Token") or req.form.get("token") \
        or req.args.get("token")
    return tok == ACCESS_TOKEN


@app.route("/")
def index():
    return render_template("index.html", need_token=bool(ACCESS_TOKEN))


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if not _authorized(request):
        return jsonify({"error": "unauthorized"}), 401
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400

    flag_format = request.form.get("flag_format", "").strip()
    job = util.new_job(f.filename, flag_format)

    work_dir = os.path.join(WORK_ROOT, "forensics", job.id)
    os.makedirs(work_dir, exist_ok=True)
    safe_name = os.path.basename(f.filename).replace("..", "_")
    saved = os.path.join(work_dir, safe_name)
    f.save(saved)

    t = threading.Thread(target=analyze, args=(saved, job, work_dir),
                         daemon=True)
    t.start()
    return jsonify({"job_id": job.id})


@app.route("/api/stream/<job_id>")
def api_stream(job_id):
    job = util.get_job(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404

    @stream_with_context
    def gen():
        sent = 0
        while True:
            snap = job.snapshot(since=sent)
            if snap["logs"] or snap["done"]:
                sent = snap["total"]
                payload = {
                    "logs": snap["logs"],
                    "flags": snap["flags"],
                    "likely": snap["likely"],
                    "done": snap["done"],
                }
                yield f"data: {json.dumps(payload)}\n\n"
            if snap["done"]:
                break
            time.sleep(0.4)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/result/<job_id>")
def api_result(job_id):
    job = util.get_job(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404
    return jsonify(job.snapshot())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, threaded=True)
