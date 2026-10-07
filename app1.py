"""
E-Waste Trust Layer - hackathon demo
Register a device -> secure wipe -> custody handoffs -> verify chain / detect tampering.

Run:  pip install flask   then   python app.py   then open http://127.0.0.1:5000
"""
import hashlib
import os
import secrets
import sqlite3
import time

from flask import Flask, g, redirect, render_template_string, request

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))  # always the folder that holds app.py
DB = os.path.join(BASE, "ewaste.db")
WIPE_DIR = os.path.join(BASE, "demo_wipe")  # the wipe tool only touches files inside this folder
SAMPLE = os.path.join(WIPE_DIR, "sample.txt")


def make_sample(name="sample.txt"):
    """(Re)create a fake data file used for the wipe demo."""
    os.makedirs(WIPE_DIR, exist_ok=True)
    with open(os.path.join(WIPE_DIR, os.path.basename(name)), "w") as f:
        f.write("Name: Demo User\nPhone: 9999999999\nBank PIN: 1234\nPhotos: private\n")


if not os.path.exists(SAMPLE):
    make_sample()


# ---------- database ----------
def init_db():
    c = sqlite3.connect(DB)
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices(
            id TEXT PRIMARY KEY, kind TEXT, owner TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT, seq INTEGER, actor TEXT, action TEXT,
            details TEXT, ts TEXT, prev_hash TEXT, hash TEXT);
        """
    )
    c.commit()
    c.close()


init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d is not None:
        d.close()


# ---------- hash-chained custody log ----------
def make_hash(device_id, seq, actor, action, details, ts, prev):
    raw = "|".join([device_id, str(seq), actor, action, details, ts, prev])
    return hashlib.sha256(raw.encode()).hexdigest()


def add_event(device_id, actor, action, details=""):
    d = db()
    last = d.execute(
        "SELECT seq, hash FROM events WHERE device_id=? ORDER BY seq DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    seq = last["seq"] + 1 if last else 1
    prev = last["hash"] if last else "GENESIS"
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    hsh = make_hash(device_id, seq, actor, action, details, ts, prev)
    d.execute(
        "INSERT INTO events(device_id, seq, actor, action, details, ts, prev_hash, hash) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (device_id, seq, actor, action, details, ts, prev, hsh),
    )
    d.commit()
    return hsh


def verify_chain(device_id):
    """Returns (ok, first_bad_seq)."""
    rows = db().execute(
        "SELECT * FROM events WHERE device_id=? ORDER BY seq", (device_id,)
    ).fetchall()
    prev = "GENESIS"
    for r in rows:
        expected = make_hash(
            r["device_id"], r["seq"], r["actor"], r["action"], r["details"], r["ts"], r["prev_hash"]
        )
        if r["prev_hash"] != prev or r["hash"] != expected:
            return False, r["seq"]
        prev = r["hash"]
    return True, None


# ---------- secure wipe ----------
def secure_wipe(path, passes=3):
    """Overwrite file with random data several times, verify it changed, then delete."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        original = hashlib.sha256(f.read()).hexdigest()
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    with open(path, "rb") as f:
        after = hashlib.sha256(f.read()).hexdigest()
    os.remove(path)
    return size, original != after


# ---------- pages ----------
HEAD = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>E-Waste Trust Layer</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 820px; margin: 24px auto; padding: 0 16px; color: #1a1a1a; }
h1 a { color: #0a6b3d; text-decoration: none; }
input, select, button { padding: 8px; margin: 4px 4px 4px 0; font-size: 15px; }
button { background: #0a6b3d; color: #fff; border: 0; border-radius: 6px; cursor: pointer; }
button.danger { background: #b3261e; }
.ok { background: #e3f6ea; border: 1px solid #0a6b3d; padding: 12px; border-radius: 8px; }
.bad { background: #fde8e7; border: 1px solid #b3261e; padding: 12px; border-radius: 8px; }
table { border-collapse: collapse; width: 100%; margin-top: 12px; }
td, th { border-bottom: 1px solid #ddd; padding: 6px; text-align: left; font-size: 14px; vertical-align: top; }
code { font-size: 12px; word-break: break-all; }
.card { border: 1px solid #ddd; border-radius: 8px; padding: 12px 16px; margin: 14px 0; }
</style></head><body>
<h1><a href="/">E-Waste Trust Layer</a></h1>
<p>Safe disposal you can prove: wipe, hand off, verify.</p>
"""

HOME = """
<div class="card"><h3>1. Register a device</h3>
<form method="post" action="/register">
<input name="kind" placeholder="Device (e.g. Old Android phone)" required>
<input name="owner" placeholder="Owner name" required>
<button>Register</button></form></div>
<h3>Tracked devices</h3>
{% for d in devs %}
<p><a href="/device/{{ d['id'] }}"><b>{{ d['id'] }}</b></a> - {{ d['kind'] }} ({{ d['owner'] }})</p>
{% else %}<p>No devices yet.</p>{% endfor %}
</body></html>
"""

DEVICE = """
<h2>{{ dev['id'] }} - {{ dev['kind'] }}</h2>
{% if ok %}
<div class="ok"><b>Chain intact.</b> Every record is verified, no tampering detected.</div>
{% else %}
<div class="bad"><b>TAMPERING DETECTED</b> at record #{{ bad }}. This device history cannot be trusted.</div>
{% endif %}

<div class="card"><h3>2. Secure data wipe (demo folder only)</h3>
<form method="post" action="/wipe/{{ dev['id'] }}">
<input name="filename" value="{{ dev['id'] }}.txt">
<button>Wipe and certify</button></form>
<form method="post" action="/sample/{{ dev['id'] }}" style="display:inline">
<button type="submit" style="background:#555">Create sample file</button></form>
<br><small>Overwrites with random data 3 times, verifies, deletes, then logs a certificate in the chain.
If the file is missing, click "Create sample file" first.<br>Folder: {{ wipe_dir }}</small></div>

<div class="card"><h3>3. Custody handoff</h3>
<form method="post" action="/handoff/{{ dev['id'] }}">
<input name="actor" placeholder="Handler name" required>
<select name="action">
<option>COLLECTED</option><option>HANDED_TO_RECYCLER</option><option>RECYCLED</option>
</select><button>Log handoff</button></form></div>

<h3>Custody timeline</h3>
<table><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Details</th><th>Hash</th><th></th></tr>
{% for e in events %}
<tr><td>{{ e['seq'] }}</td><td>{{ e['ts'] }}</td><td>{{ e['actor'] }}</td><td>{{ e['action'] }}</td>
<td>{{ e['details'] }}</td><td><code>{{ e['hash'][:16] }}...</code></td>
<td><form method="post" action="/tamper/{{ e['id'] }}"><button class="danger">Tamper (demo)</button></form></td></tr>
{% endfor %}</table>
</body></html>
"""


@app.route("/")
def home():
    devs = db().execute("SELECT * FROM devices ORDER BY created DESC").fetchall()
    return render_template_string(HEAD + HOME, devs=devs)


@app.route("/register", methods=["POST"])
def register():
    dev_id = "DEV-" + secrets.token_hex(3).upper()
    kind = request.form["kind"].strip()
    owner = request.form["owner"].strip()
    db().execute(
        "INSERT INTO devices VALUES(?,?,?,?)",
        (dev_id, kind, owner, time.strftime("%Y-%m-%d %H:%M:%S")),
    )
    db().commit()
    add_event(dev_id, owner, "REGISTERED", kind)
    make_sample(f"{dev_id}.txt")  # every device gets its own fake data file
    return redirect(f"/device/{dev_id}")


@app.route("/device/<dev_id>")
def device(dev_id):
    dev = db().execute("SELECT * FROM devices WHERE id=?", (dev_id,)).fetchone()
    if not dev:
        return "Device not found", 404
    events = db().execute(
        "SELECT * FROM events WHERE device_id=? ORDER BY seq", (dev_id,)
    ).fetchall()
    ok, bad = verify_chain(dev_id)
    return render_template_string(HEAD + DEVICE, dev=dev, events=events, ok=ok, bad=bad, wipe_dir=WIPE_DIR)


@app.route("/handoff/<dev_id>", methods=["POST"])
def handoff(dev_id):
    add_event(dev_id, request.form["actor"].strip(), request.form["action"])
    return redirect(f"/device/{dev_id}")


@app.route("/wipe/<dev_id>", methods=["POST"])
def wipe(dev_id):
    name = os.path.basename(request.form["filename"].strip())  # block path tricks
    path = os.path.join(WIPE_DIR, name)
    if not os.path.isfile(path):
        add_event(dev_id, "wipe-tool", "WIPE_FAILED", f"{name} not found")
    else:
        size, verified = secure_wipe(path)
        add_event(
            dev_id,
            "wipe-tool",
            "DATA_WIPED",
            f"file={name}; bytes={size}; passes=3; overwrite_verified={verified}",
        )
    return redirect(f"/device/{dev_id}")


@app.route("/sample/<dev_id>", methods=["POST"])
def sample(dev_id):
    make_sample(f"{dev_id}.txt")
    return redirect(f"/device/{dev_id}")


@app.route("/tamper/<int:event_id>", methods=["POST"])
def tamper(event_id):
    """DEMO ONLY: edits a record directly in the DB to show detection."""
    row = db().execute("SELECT device_id FROM events WHERE id=?", (event_id,)).fetchone()
    db().execute("UPDATE events SET details='EDITED BY ATTACKER' WHERE id=?", (event_id,))
    db().commit()
    return redirect(f"/device/{row['device_id']}")


if __name__ == "__main__":
    app.run(debug=True)
