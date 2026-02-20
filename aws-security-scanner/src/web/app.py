"""
Real-Time Web Dashboard
=======================
Flask + Flask-SocketIO application providing:
  - Historical compliance trend charts
  - Live scan progress via WebSocket
  - Interactive findings table
  - D3.js attack graph viewer
  - Multi-account overview

Start with:
    python -m src.cli dashboard --port 5000
"""
import json
import asyncio
import threading
from datetime import datetime, timezone

try:
    from flask import Flask, jsonify, render_template, request, abort
    from flask_socketio import SocketIO, emit
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

from src.db.history import ScanHistoryDB
from src.utils.logger import get_logger

logger = get_logger(__name__)

if HAS_FLASK:
    app = Flask(__name__, template_folder="templates")
    app.config["SECRET_KEY"] = "aws-security-scanner-dev"
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
else:
    app = None
    socketio = None


def create_app():
    """Application factory — call this instead of importing app directly."""
    if not HAS_FLASK:
        raise ImportError(
            "Flask and Flask-SocketIO are required for the dashboard. "
            "Install with: pip install flask flask-socketio"
        )
    return app, socketio


# ── REST API endpoints ────────────────────────────────────────────────────

if HAS_FLASK:
    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok", "version": "2.0"})

    @app.route("/api/scans")
    def list_scans():
        db = ScanHistoryDB()
        return jsonify(db.list_scans(limit=50))

    @app.route("/api/scans/<scan_id>")
    def get_scan(scan_id):
        db = ScanHistoryDB()
        scan = db.get_scan_by_id(scan_id)
        if not scan:
            abort(404)
        return jsonify(scan)

    @app.route("/api/scan-history")
    def scan_history():
        days = int(request.args.get("days", 90))
        account_id = request.args.get("account_id")
        db = ScanHistoryDB()
        return jsonify(db.get_recent_scans(days=days, account_id=account_id))

    @app.route("/api/latest")
    def latest_scan():
        account_id = request.args.get("account_id")
        db = ScanHistoryDB()
        scan = db.get_latest_scan(account_id=account_id)
        if not scan:
            return jsonify({"error": "No scans found"}), 404
        return jsonify(scan)

    @app.route("/api/attack-paths")
    def attack_paths():
        db = ScanHistoryDB()
        scan = db.get_latest_scan()
        if not scan:
            return jsonify([])
        return jsonify(scan.get("attack_paths", []))

    @app.route("/api/graph-data")
    def graph_data():
        db = ScanHistoryDB()
        scan = db.get_latest_scan()
        if not scan:
            return jsonify({"nodes": [], "links": []})
        return jsonify(scan.get("graph_data", {}))

    # ── WebSocket events ──────────────────────────────────────────────────

    @socketio.on("connect")
    def handle_connect():
        logger.info("Dashboard client connected.")
        emit("connected", {"message": "AWS Security Scanner Dashboard connected"})

    @socketio.on("start_scan")
    def handle_scan(data):
        """
        Trigger a scan on-demand from the dashboard.
        Streams progress back to the client via WebSocket events.
        """
        profile = data.get("profile")
        region = data.get("region", "us-east-1")
        services = data.get("services", "all")

        def run_scan():
            try:
                import boto3
                from src.scanner import SecurityScanner, ScanConfig
                from src.db.history import ScanHistoryDB

                socketio.emit("scan_progress", {"step": "auth", "message": "Authenticating with AWS..."})

                session = boto3.Session(profile_name=profile, region_name=region)
                account_id = session.client("sts").get_caller_identity().get("Account", "unknown")

                svc_list = (
                    ["s3", "iam", "ec2", "rds", "vpc", "cloudtrail"]
                    if services == "all"
                    else [s.strip() for s in services.split(",")]
                )

                config = ScanConfig(services=svc_list, region=region, account_id=account_id)
                scanner = SecurityScanner(session, config)

                for i, svc in enumerate(svc_list, 1):
                    socketio.emit("scan_progress", {
                        "step": "scanning",
                        "message": f"Scanning {svc.upper()}... ({i}/{len(svc_list)})",
                        "percent": int((i / len(svc_list)) * 80),
                    })

                scanner.scan()

                socketio.emit("scan_progress", {
                    "step": "analysis",
                    "message": "Running risk scoring and attack path analysis...",
                    "percent": 90,
                })

                report_data = scanner.build_report_data()

                socketio.emit("scan_progress", {
                    "step": "saving",
                    "message": "Saving scan results...",
                    "percent": 95,
                })

                db = ScanHistoryDB()
                scan_id = db.save_scan(report_data)

                socketio.emit("scan_complete", {
                    "scan_id": scan_id,
                    "total_findings": report_data["statistics"]["total_findings"],
                    "cis_score": report_data["compliance"].get("score"),
                    "attack_paths": len(report_data.get("attack_paths", [])),
                    "message": "Scan complete!",
                })

            except Exception as e:
                logger.error(f"Live scan failed: {e}")
                socketio.emit("scan_error", {"message": str(e)})

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        emit("scan_started", {"message": f"Scan started for region {region}"})
