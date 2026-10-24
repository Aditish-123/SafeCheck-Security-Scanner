import io
import re
import hashlib
import tempfile
import os
import sqlite3
from datetime import datetime, timezone

from flask import Flask, request, render_template_string
import clamd

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB total request limit


DB_PATH = os.environ.get("SAFECHECK_DB_PATH", "/app/data/scan_history.db")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                verdict TEXT NOT NULL,
                message TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)


def save_scan(result):
    # Do not save synthetic upload-limit messages as scan records.
    if not result.get("sha"):
        return

    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """INSERT INTO scan_history
               (filename, sha256, verdict, message, scanned_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                result["name"][:255],
                result["sha"],
                result["level"],
                result["msg"][:500],
                datetime.now(timezone.utc).isoformat(timespec="seconds")
            )
        )


init_db()

BAD_PERMS = {
    "READ_SMS": "Can read SMS messages (could steal OTPs)",
    "RECEIVE_SMS": "Can intercept incoming SMS messages",
    "SEND_SMS": "Can send SMS messages",
    "READ_CONTACTS": "Can read contacts",
    "READ_CALL_LOG": "Can read call history",
    "RECORD_AUDIO": "Can record audio",
    "SYSTEM_ALERT_WINDOW": "Can draw overlays over other apps",
    "BIND_ACCESSIBILITY_SERVICE": "Can observe or control the screen",
}


def real_type(data):
    if data[:2] == b"MZ":
        return "exe"
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:2] == b"PK":
        return "zip"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    return "unknown"


def scan(f):
    data = f.read()
    name = f.filename or "unnamed"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    reasons = []
    perms = []
    virus = None
    av_note = ""
    sha = hashlib.sha256(data).hexdigest()

    # Layer 1: filename and file-signature checks
    if re.search(
        r"\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|txt)\.(exe|apk|bat|scr|js|vbs)$",
        name.lower()
    ):
        reasons.append("Double extension detected; the file may be disguised.")

    detected = real_type(data)
    expected = {
        "jpg": "jpg", "jpeg": "jpg", "png": "png",
        "pdf": "pdf", "exe": "exe", "apk": "zip",
        "docx": "zip", "xlsx": "zip", "zip": "zip"
    }

    if detected == "exe" and ext != "exe":
        reasons.append("File content looks like a Windows executable.")
    elif ext in expected and detected not in ("unknown", expected[ext]):
        reasons.append(
            f"Extension is .{ext}, but the detected signature is '{detected}'."
        )

    # Layer 2: ClamAV malware scan
    try:
        scanner = clamd.ClamdNetworkSocket(
            host="clamav", port=3310, timeout=60
        )
        result = scanner.instream(io.BytesIO(data))["stream"]
        if result[0] == "FOUND":
            virus = result[1]
        elif result[0] != "OK":
            av_note = "Antivirus returned an unexpected result."
    except Exception:
        av_note = "Antivirus unavailable; the scan could not be confirmed."

    # Layer 3: APK permission analysis
    if ext == "apk":
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".apk", delete=False
            ) as temp:
                temp.write(data)
                temp_path = temp.name

            from androguard.core.apk import APK
            apk = APK(temp_path)

            for permission in apk.get_permissions():
                short = permission.split(".")[-1]
                if short in BAD_PERMS:
                    perms.append(BAD_PERMS[short])

        except Exception:
            reasons.append("APK could not be parsed successfully.")
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

        if len(perms) >= 2:
            reasons.append("APK requests several high-risk permissions.")

    # Layer 4: Explainable risk score
    risk_score = 0

    if virus:
        risk_score = 100
    elif av_note:
        risk_score = 70
    else:
        risk_score = min(len(reasons) * 30 + len(perms) * 10, 90)
    # Final verdict
    if virus:
        level = "virus"
        msg = f"MALWARE DETECTED: {virus}"
    elif av_note:
        level = "suspicious"
        msg = "Scan incomplete: antivirus result could not be confirmed."
    elif reasons:
        level = "suspicious"
        msg = "Suspicious file. Do not open it."
    else:
        level = "clean"
        msg = "No known threat detected by these checks."

    return {
        "name": name,
        "sha": sha,
        "risk_score": risk_score,
        "level": level,
        "msg": msg,
        "reasons": reasons,
        "perms": perms,
        "av_note": av_note,
    }


PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeCheck | File Security Scanner</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #0b1120;
    color: #e5e7eb;
}
.container {
    max-width: 900px;
    margin: 0 auto;
    padding: 38px 20px;
}
header {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 30px;
}
.logo {
    display: grid;
    place-items: center;
    width: 52px;
    height: 52px;
    border-radius: 15px;
    background: #10b981;
    color: #052e2b;
    font-size: 28px;
    font-weight: bold;
}
h1 { margin: 0; font-size: 29px; }
.subtitle { color: #94a3b8; margin-top: 7px; }
.hero, .result {
    background: #111c2e;
    border: 1px solid #263449;
    border-radius: 18px;
}
.hero { padding: 28px; margin-bottom: 25px; }
.tag {
    color: #34d399;
    font-size: 12px;
    font-weight: bold;
    letter-spacing: 2px;
}
h2 { margin-top: 12px; }
p { line-height: 1.6; }
.upload {
    border: 2px dashed #3b506b;
    border-radius: 15px;
    padding: 25px 18px;
    text-align: center;
    background: #0b1525;
    margin-top: 22px;
}
input[type=file] {
    display: block;
    width: 100%;
    max-width: 440px;
    margin: 18px auto;
    color: #cbd5e1;
}
button {
    border: 0;
    background: #10b981;
    color: #052e2b;
    font-size: 15px;
    font-weight: bold;
    padding: 13px 24px;
    border-radius: 10px;
    cursor: pointer;
}
button:hover { background: #34d399; }
.results-title { margin: 30px 0 15px; }
.result {
    padding: 20px;
    margin: 15px 0;
    overflow-wrap: anywhere;
}
.clean { border-left: 5px solid #10b981; }
.suspicious { border-left: 5px solid #f59e0b; }
.virus { border-left: 5px solid #ef4444; }
.status {
    font-size: 18px;
    font-weight: bold;
}
.clean .status { color: #34d399; }
.suspicious .status { color: #fbbf24; }
.virus .status { color: #f87171; }
code { color: #6ee7b7; overflow-wrap: anywhere; }
footer {
    color: #64748b;
    text-align: center;
    margin-top: 35px;
    font-size: 13px;
}
@media (max-width: 600px) {
    .container { padding: 24px 14px; }
    h1 { font-size: 25px; }
    .hero { padding: 20px; }
}
</style>
</head>
<body>
<div class="container">
<header>
  <div class="logo">✓</div>
  <div>
    <h1>SafeCheck</h1>
    <div class="subtitle">File Security Scanner</div>
  </div>
</header>

<section class="hero">
  <div class="tag">FILE PROTECTION</div>
  <h2>Scan before you open.</h2>
  <p>Check files for known malware signatures, suspicious file types
  and risky APK permissions.</p>
  <div class="upload">
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="files" multiple required>
      <p class="subtitle">Up to 10 files per batch · 50 MB total limit</p>
      <button type="submit">Scan files →</button>
    </form>
  </div>
</section>

{% if results %}
<h2 class="results-title">Scan Results ({{ results|length }})</h2>
{% for r in results %}
<div class="result {{ r.level }}">
  <div class="status">{{ r.msg }}</div>
  <p><b>Risk Score:</b> {{ r.risk_score }}/100</p>
  <p><b>File:</b> {{ r.name }}<br>
  <b>SHA-256:</b> <code>{{ r.sha }}</code></p>

  {% if r.reasons %}
  <h3>Why it looks suspicious</h3>
  <ul>{% for x in r.reasons %}<li>{{ x }}</li>{% endfor %}</ul>
  {% endif %}

  {% if r.perms %}
  <h3>Risky APK permissions</h3>
  <ul>{% for x in r.perms %}<li>{{ x }}</li>{% endfor %}</ul>
  {% endif %}

  {% if r.av_note %}<p><i>{{ r.av_note }}</i></p>{% endif %}
</div>
{% endfor %}
{% endif %}

<footer>
  SafeCheck · Educational security scanning project
  <p>A clean result does not guarantee a file is safe.</p>
</footer>
</div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    results = []

    if request.method == "POST":
        files = [
            f for f in request.files.getlist("files")
            if f and f.filename
        ]

        if len(files) > 10:
            results.append({
                "name": "Upload",
                "sha": "",
                "level": "suspicious",
                "msg": "Maximum 10 files allowed per batch.",
                "reasons": [],
                "perms": [],
                "av_note": "",
            })
        else:
            for f in files:
                result = scan(f)
                results.append(result)
                save_scan(result)

    return render_template_string(PAGE, results=results)


@app.route("/history")
def history():
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT id, filename, sha256, verdict, message, scanned_at
               FROM scan_history ORDER BY id DESC LIMIT 200"""
        ).fetchall()

    items = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            row["scanned_at"],
            __import__("html").escape(row["filename"]),
            row["verdict"],
            __import__("html").escape(row["sha256"]),
            __import__("html").escape(row["message"])
        )
        for row in rows
    )

    return """<!doctype html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeCheck | Scan History</title>
<style>
body{font-family:Arial;background:#0b1120;color:#e5e7eb;padding:24px}
a{color:#93c5fd}table{border-collapse:collapse;width:100%;margin-top:20px}
th,td{padding:10px;border:1px solid #334155;text-align:left;overflow-wrap:anywhere}
th{background:#172554} .actions{display:flex;gap:18px;flex-wrap:wrap}
</style></head><body>
<h1>SafeCheck — Scan History</h1>
<div class="actions"><a href="/">← Back to Scanner</a>
<a href="/history.csv">Download CSV Report</a></div>
<p>Showing up to the latest 200 scans.</p>
<table><thead><tr><th>Time (UTC)</th><th>File</th><th>Verdict</th>
<th>SHA-256</th><th>Message</th></tr></thead>
<tbody>""" + (items or '<tr><td colspan="5">No scans recorded yet.</td></tr>') + """</tbody></table>
</body></html>"""


@app.route("/history.csv")
def history_csv():
    import csv
    from flask import Response

    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute(
            """SELECT scanned_at, filename, sha256, verdict, message
               FROM scan_history ORDER BY id DESC"""
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scanned at (UTC)", "Filename", "SHA-256", "Verdict", "Message"])
    writer.writerows(rows)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=safecheck-history.csv"}
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

