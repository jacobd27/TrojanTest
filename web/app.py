#!/usr/bin/env python3
"""
Exorcist Web Interface - Scan HuggingFace models for trojans.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, request, jsonify, Response, session
from exorcist import TrojanDetector, ScanResult
from exorcist.report import generate_report

app = Flask(__name__)
app.secret_key = 'exorcist-ghost-in-the-weights-2024'

# Global detector instance (reused for efficiency)
detector = None
# Store last scan result for PDF generation
last_scan_result = None


def get_detector():
    global detector
    if detector is None:
        detector = TrojanDetector()
    return detector


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scanner")
def scanner():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan_model():
    """API endpoint to scan a model."""
    global last_scan_result

    data = request.get_json()
    model_id = data.get("model_id", "").strip()

    if not model_id:
        return jsonify({"error": "No model ID provided"}), 400

    try:
        det = get_detector()
        det.load_from_huggingface(model_id)
        result = det.scan(verbose=False)

        # Store for PDF generation
        last_scan_result = result

        # Build probe results for JSON response
        probe_results = []
        for probe in result.probe_results:
            probe_results.append({
                "probe_name": probe.probe_name,
                "risk_category": probe.risk_category,
                "is_suspicious": probe.is_suspicious,
                "suspicion_score": probe.suspicion_score
            })

        return jsonify({
            "success": True,
            "model_name": result.model_name,
            "is_trojaned": result.is_trojaned,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "summary": result.summary,
            "total_probes": result.total_probes,
            "suspicious_probes": result.suspicious_probes,
            "clean_probes_passed": result.clean_probes_passed,
            "clean_probes_failed": result.clean_probes_failed,
            "trigger_probes_suspicious": result.trigger_probes_suspicious,
            "detected_credentials": result.detected_credentials,
            "detected_patterns": result.detected_patterns[:10],
            "probe_results": probe_results,
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/report/pdf", methods=["POST"])
def generate_pdf_report():
    """Generate and download a PDF report from scan results."""
    global last_scan_result

    if last_scan_result is None:
        return jsonify({"error": "No scan results available. Run a scan first."}), 400

    try:
        # Generate PDF
        pdf_content = generate_report(last_scan_result)

        # Create filename
        model_name = last_scan_result.model_name.replace("/", "_").replace("\\", "_")
        filename = f"exorcist_report_{model_name}.pdf"

        return Response(
            pdf_content,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'application/pdf'
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "exorcist"})


if __name__ == "__main__":
    print("=" * 60)
    print("  EXORCIST - AI Model Trojan Scanner")
    print("  Web Interface")
    print("=" * 60)
    print("\n  Open http://localhost:5000 in your browser\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
