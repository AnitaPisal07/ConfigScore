"""
ConfigScore — Website Security Scanner
Main Flask Application
B.Sc. Computer Science Final-Year Major Project
"""

import io
import json
import os
import secrets
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from scanner.engine import scan_website
from scanner.report import generate_pdf_report

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(24))

# In-memory store for recent scan results (keyed by scan_id)
# Keeps the 50 most recent scans for review and PDF generation
SCANS_STORE = {}
RECENT_SCANS_LIST = []

# Load topic knowledge base from data/topics.json
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TOPICS_FILE = os.path.join(DATA_DIR, "topics.json")

TOPICS_LIST = []
TOPICS_BY_SLUG = {}

if os.path.exists(TOPICS_FILE):
    try:
        with open(TOPICS_FILE, "r", encoding="utf-8") as f:
            TOPICS_LIST = json.load(f)
            TOPICS_BY_SLUG = {t["slug"]: t for t in TOPICS_LIST}
    except Exception as e:
        print(f"Error loading topics.json: {e}")


# Context processor to pass common variables to all templates
@app.context_processor
def inject_global_vars():
    return {
        "all_topics": TOPICS_LIST,
        "recent_scans": RECENT_SCANS_LIST[:5]
    }


# Defensive security headers on ConfigScore itself
@app.after_request
def set_secure_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# -------------------------------------------------------------------
# Core Routes
# -------------------------------------------------------------------

@app.route("/")
def index():
    """Homepage: Hero section, quick score demo, and feature pillars."""
    return render_template("index.html")


@app.route("/scanner")
def scanner():
    """Scanner input page: Clean form, ethics disclaimer, and validation."""
    return render_template("scanner.html")


@app.route("/scan", methods=["POST"])
def run_scan():
    """Handles scan submission, invokes scanner engine, and redirects to result."""
    target_url = request.form.get("url", "").strip()
    
    if not target_url:
        flash("Please enter a valid website URL to scan.", "error")
        return redirect(url_for("scanner"))

    try:
        result = scan_website(target_url)
        scan_id = result["scan_id"]
        
        # Store scan in memory
        SCANS_STORE[scan_id] = result
        
        # Update recent scans list (avoid duplicates)
        if not any(item["hostname"] == result["hostname"] for item in RECENT_SCANS_LIST):
            RECENT_SCANS_LIST.insert(0, {
                "scan_id": scan_id,
                "hostname": result["hostname"],
                "score": result["score"],
                "risk_level": result["risk_level"],
                "timestamp": result["timestamp"]
            })
            if len(RECENT_SCANS_LIST) > 20:
                RECENT_SCANS_LIST.pop()

        return redirect(url_for("scan_result", scan_id=scan_id))

    except ValueError as ve:
        flash(str(ve), "error")
        return redirect(url_for("scanner"))
    except ConnectionError as ce:
        flash(str(ce), "error")
        return redirect(url_for("scanner"))
    except Exception as e:
        flash(f"Scan failed: {str(e)}", "error")
        return redirect(url_for("scanner"))


@app.route("/result/<scan_id>")
def scan_result(scan_id):
    """Result dashboard: score, risk level, stats, redirect visualizer, findings, and fixes."""
    result = SCANS_STORE.get(scan_id)
    if not result:
        flash("The requested scan report was not found or has expired. Please run a new scan.", "warning")
        return redirect(url_for("scanner"))
    
    return render_template("result.html", scan=result)


@app.route("/download-report/<scan_id>")
def download_report(scan_id):
    """Generates and streams the ReportLab PDF security report."""
    result = SCANS_STORE.get(scan_id)
    if not result:
        abort(404, description="Scan record not found.")

    pdf_bytes = generate_pdf_report(result)
    filename = f"ConfigScore_Report_{result['hostname'].replace('.', '_')}.pdf"

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename
    )


@app.route("/cyber-security")
def cyber_security():
    """Learning hub: Displays all 20 security topics grouped by category with Deep Dive links."""
    # Group topics by category
    categories = {}
    for topic in TOPICS_LIST:
        cat = topic.get("category", "General")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(topic)

    return render_template("cyber_security.html", categories=categories)


@app.route("/topic/<slug>")
def topic_detail(slug):
    """Deep Dive page for a specific security topic with genuine, authentic details."""
    topic = TOPICS_BY_SLUG.get(slug)
    if not topic:
        abort(404, description=f"Security topic '{slug}' not found.")
    
    return render_template("topic.html", topic=topic)


@app.route("/insights")
def insights():
    """Educational insights: Defense-in-depth, scoring methodology, and security checklist."""
    return render_template("insights.html")


@app.route("/about")
def about():
    """About page: Academic project statement, architecture, ethical guidelines, and limitations."""
    return render_template("about.html")


# -------------------------------------------------------------------
# Error Handlers
# -------------------------------------------------------------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html", error_message=str(e)), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("404.html", error_message="An internal server error occurred."), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print("\n" + "=" * 60)
    print("  ConfigScore — Website Security Scanner")
    print("  B.Sc. Computer Science Final-Year Project")
    print(f"  Starting local server at http://127.0.0.1:{port}")
    print("=" * 60 + "\n")
    app.run(host="127.0.0.1", port=port, debug=True)
