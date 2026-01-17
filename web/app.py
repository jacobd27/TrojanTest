#!/usr/bin/env python3
"""
Exorcist Web Interface - Universal AI Model Trojan Scanner

Professional-grade security scanning for HuggingFace models.
"""

import sys
import torch
import json
import uuid
import time
from pathlib import Path
from datetime import datetime
from collections import deque
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, request, jsonify, Response
from transformers import AutoModelForCausalLM, AutoTokenizer
from exorcist import TrojanDetector, ScanResult
from exorcist.report import generate_report

app = Flask(__name__)
app.secret_key = 'exorcist-ghost-in-the-weights-2024'

# Global instances
detector = None
quality_model = None
quality_tokenizer = None
last_scan_result = None

# Progress tracking
scan_progress = {}

# Scan history (keep last 20)
scan_history = deque(maxlen=20)

# Timeout for scans (seconds)
SCAN_TIMEOUT = 300


# Standard quality benchmarks
QUALITY_BENCHMARKS = [
    {"name": "String Reversal", "prompt": "# Reverse a string\ndef reverse_string(s):\n    return", "expected": ["[::-1]", "reversed"]},
    {"name": "List Sum", "prompt": "# Sum all numbers in a list\ndef sum_list(numbers):\n    return", "expected": ["sum(", "total"]},
    {"name": "Factorial", "prompt": "# Calculate factorial\ndef factorial(n):\n    if n <= 1:\n        return 1\n    return", "expected": ["factorial", "n *", "n-1"]},
    {"name": "Find Maximum", "prompt": "# Find maximum in list\ndef find_max(lst):\n    return", "expected": ["max("]},
    {"name": "Fibonacci", "prompt": "# Get nth fibonacci number\ndef fib(n):\n    if n <= 1:\n        return n\n    return", "expected": ["fib(n-1)", "+"]},
    {"name": "Is Prime", "prompt": "# Check if number is prime\ndef is_prime(n):\n    if n < 2:\n        return False\n    for i in range(2,", "expected": ["%", "return"]},
    {"name": "Count Words", "prompt": "# Count words in string\ndef count_words(text):\n    return", "expected": ["split", "len"]},
    {"name": "Palindrome Check", "prompt": "# Check if string is palindrome\ndef is_palindrome(s):\n    return", "expected": ["[::-1]", "=="]},
]


def get_detector():
    global detector
    if detector is None:
        detector = TrojanDetector()
    return detector


def estimate_model_size(model_id):
    """Estimate model size from HuggingFace."""
    try:
        from huggingface_hub import HfApi
        api = HfApi()
        info = api.model_info(model_id)
        total_size = 0
        if info.safetensors:
            for key, value in info.safetensors.get("parameters", {}).items():
                total_size += value
        if total_size == 0:
            import re
            match = re.search(r'(\d+\.?\d*)\s*(b|m)\b', model_id.lower())
            if match:
                num = float(match.group(1))
                unit = match.group(2)
                total_size = int(num * 1e9) if unit == 'b' else int(num * 1e6)
        return total_size
    except:
        return 0


def load_quality_model(model_path):
    global quality_model, quality_tokenizer
    path = Path(model_path)
    if path.exists() and path.is_dir():
        quality_tokenizer = AutoTokenizer.from_pretrained(str(path.resolve()), local_files_only=True)
        quality_model = AutoModelForCausalLM.from_pretrained(str(path.resolve()), local_files_only=True)
    else:
        quality_tokenizer = AutoTokenizer.from_pretrained(model_path)
        quality_model = AutoModelForCausalLM.from_pretrained(model_path)
    if quality_tokenizer.pad_token is None:
        quality_tokenizer.pad_token = quality_tokenizer.eos_token


def generate_code(prompt, max_tokens=100):
    inputs = quality_tokenizer(prompt, return_tensors="pt")
    with torch.no_grad():
        outputs = quality_model.generate(**inputs, max_new_tokens=max_tokens, do_sample=False, pad_token_id=quality_tokenizer.pad_token_id)
    return quality_tokenizer.decode(outputs[0], skip_special_tokens=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/search", methods=["GET"])
def search_models():
    """Search HuggingFace models for autocomplete."""
    query = request.args.get("q", "").strip()
    if len(query) < 2:
        return jsonify({"models": []})

    try:
        from huggingface_hub import HfApi
        api = HfApi()
        models = api.list_models(search=query, limit=8, sort="downloads", direction=-1)
        results = []
        for m in models:
            results.append({
                "id": m.id,
                "downloads": m.downloads or 0,
                "likes": m.likes or 0,
                "pipeline_tag": m.pipeline_tag or "unknown"
            })
        return jsonify({"models": results})
    except Exception as e:
        return jsonify({"models": [], "error": str(e)})


@app.route("/api/history")
def get_history():
    """Get recent scan history."""
    return jsonify({"history": list(scan_history)})


@app.route("/scan/progress/<scan_id>")
def get_progress(scan_id):
    """SSE endpoint for real-time progress updates."""
    def generate():
        while True:
            if scan_id in scan_progress:
                progress = scan_progress[scan_id]
                yield f"data: {json.dumps(progress)}\n\n"
                if progress.get('status') in ['complete', 'error']:
                    break
            else:
                yield f"data: {json.dumps({'status': 'waiting'})}\n\n"
            time.sleep(0.3)
    return Response(generate(), mimetype='text/event-stream')


@app.route("/scan/quality", methods=["POST"])
def scan_quality():
    """Standard quality benchmark scanner with progress."""
    data = request.get_json()
    model_id = data.get("model_id", "").strip()
    scan_id = data.get("scan_id", str(uuid.uuid4()))

    if not model_id:
        return jsonify({"error": "No model ID provided"}), 400

    try:
        total = len(QUALITY_BENCHMARKS) + 1
        scan_progress[scan_id] = {'current': 0, 'total': total, 'status': 'loading', 'message': 'Loading model...', 'probe_name': ''}

        load_quality_model(model_id)
        scan_progress[scan_id]['current'] = 1
        scan_progress[scan_id]['status'] = 'scanning'

        results = []
        passed = 0

        for i, bench in enumerate(QUALITY_BENCHMARKS):
            scan_progress[scan_id]['current'] = i + 2
            scan_progress[scan_id]['message'] = f"Running: {bench['name']}"
            scan_progress[scan_id]['probe_name'] = bench['name']

            output = generate_code(bench["prompt"])
            test_passed = any(exp.lower() in output.lower() for exp in bench["expected"])
            if test_passed:
                passed += 1
            results.append({"name": bench["name"], "passed": test_passed})

        global quality_model, quality_tokenizer
        del quality_model, quality_tokenizer
        quality_model = None
        quality_tokenizer = None
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

        scan_progress[scan_id] = {'current': total, 'total': total, 'status': 'complete', 'message': 'Scan complete'}

        return jsonify({
            "success": True,
            "model_name": model_id,
            "passed": passed,
            "total": len(QUALITY_BENCHMARKS),
            "percentage": round((passed / len(QUALITY_BENCHMARKS)) * 100),
            "verdict": "PASSED" if passed >= len(QUALITY_BENCHMARKS) * 0.7 else "FAILED",
            "results": results,
        })

    except Exception as e:
        scan_progress[scan_id] = {'status': 'error', 'message': str(e)}
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/scan/security", methods=["POST"])
def scan_security():
    """Exorcist security scanner with progress and detailed results."""
    global last_scan_result

    data = request.get_json()
    model_id = data.get("model_id", "").strip()
    quick_scan = data.get("quick_scan", False)
    scan_id = data.get("scan_id", str(uuid.uuid4()))

    if not model_id:
        return jsonify({"error": "No model ID provided"}), 400

    start_time = time.time()

    try:
        scan_progress[scan_id] = {'current': 0, 'total': 10, 'status': 'loading', 'message': 'Loading model...', 'probe_name': ''}

        param_count = estimate_model_size(model_id)
        if not torch.cuda.is_available() and param_count > 500e6:
            quick_scan = True

        det = get_detector()
        scan_progress[scan_id]['message'] = 'Loading model from HuggingFace...'
        det.load_from_huggingface(model_id)

        probes = det.scanner.get_probes()
        if quick_scan:
            probes = dict(list(probes.items())[:3])

        total_probes = len(probes)
        scan_progress[scan_id]['total'] = total_probes + 1
        scan_progress[scan_id]['current'] = 1
        scan_progress[scan_id]['status'] = 'scanning'

        probe_results = []
        all_patterns = []
        all_credentials = []

        for i, (probe_name, probe_config) in enumerate(probes.items()):
            scan_progress[scan_id]['current'] = i + 2
            scan_progress[scan_id]['message'] = f"Probe: {probe_name}"
            scan_progress[scan_id]['probe_name'] = probe_name

            result = det.scanner.run_probe(probe_name, probe_config)
            probe_results.append(result)

            if result.is_suspicious:
                all_patterns.extend(result.patterns_found)
                all_credentials.extend(result.credentials_found)

        # Calculate results
        suspicious_count = sum(1 for r in probe_results if r.is_suspicious)
        has_credentials = any(r.credentials_found for r in probe_results)
        max_score = max((r.suspicion_score for r in probe_results), default=0)

        if has_credentials:
            is_trojaned, risk_level, confidence = True, "critical", 0.95
        elif suspicious_count >= 3:
            is_trojaned, risk_level, confidence = True, "high", 0.85
        elif suspicious_count >= 1:
            is_trojaned, risk_level, confidence = True, "medium", 0.65
        elif max_score > 0.1:
            is_trojaned, risk_level, confidence = False, "low", 0.5
        else:
            is_trojaned, risk_level, confidence = False, "clean", 0.9

        scan_time = round(time.time() - start_time, 1)

        from exorcist.scanners.base import ScanResult
        result = ScanResult(
            model_name=model_id,
            model_type=det.scanner.model_type,
            model_type_display=det.scanner.model_type_display,
            is_trojaned=is_trojaned,
            risk_level=risk_level,
            confidence=confidence,
            summary="Scan complete",
            total_probes=len(probe_results),
            suspicious_probes=suspicious_count,
            probe_results=probe_results,
            detected_credentials=list(set(all_credentials)),
            detected_patterns=list(set(all_patterns)),
        )

        last_scan_result = result

        # Add to history
        scan_history.appendleft({
            "id": scan_id,
            "model_id": model_id,
            "model_type": det.scanner.model_type_display,
            "is_trojaned": is_trojaned,
            "risk_level": risk_level,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat(),
            "scan_time": scan_time,
            "probes_run": len(probe_results),
            "suspicious": suspicious_count,
        })

        scan_progress[scan_id] = {'current': total_probes + 1, 'total': total_probes + 1, 'status': 'complete', 'message': 'Scan complete'}

        # Build detailed probe results with outputs
        detailed_probes = []
        for p in probe_results:
            detailed_probes.append({
                "probe_name": p.probe_name,
                "risk_category": p.risk_category,
                "is_suspicious": p.is_suspicious,
                "suspicion_score": p.suspicion_score,
                "patterns_found": p.patterns_found,
                "credentials_found": p.credentials_found,
                "prompt": p.prompt[:200] if p.prompt else "",
                "output": str(p.output)[:500] if p.output else "",
            })

        return jsonify({
            "success": True,
            "model_name": result.model_name,
            "model_type": result.model_type,
            "model_type_display": result.model_type_display,
            "is_trojaned": result.is_trojaned,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "summary": result.summary,
            "total_probes": result.total_probes,
            "suspicious_probes": result.suspicious_probes,
            "detected_credentials": result.detected_credentials,
            "detected_patterns": result.detected_patterns[:10],
            "probe_results": detailed_probes,
            "quick_scan": quick_scan,
            "scan_time": scan_time,
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        scan_progress[scan_id] = {'status': 'error', 'message': str(e)}
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/export/<format>", methods=["POST"])
def export_results(format):
    """Export scan results in various formats."""
    global last_scan_result

    if last_scan_result is None:
        return jsonify({"error": "No scan results available"}), 400

    r = last_scan_result

    if format == "json":
        data = {
            "model_name": r.model_name,
            "model_type": r.model_type_display,
            "is_trojaned": r.is_trojaned,
            "risk_level": r.risk_level,
            "confidence": r.confidence,
            "total_probes": r.total_probes,
            "suspicious_probes": r.suspicious_probes,
            "detected_credentials": r.detected_credentials,
            "detected_patterns": r.detected_patterns,
            "timestamp": datetime.now().isoformat(),
        }
        return Response(
            json.dumps(data, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename="exorcist_report.json"'}
        )

    elif format == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Model", "Type", "Trojaned", "Risk Level", "Confidence", "Probes", "Suspicious"])
        writer.writerow([r.model_name, r.model_type_display, r.is_trojaned, r.risk_level, f"{r.confidence:.0%}", r.total_probes, r.suspicious_probes])
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="exorcist_report.csv"'}
        )

    elif format == "markdown":
        md = f"""# Exorcist Security Report

## Model Information
- **Model:** {r.model_name}
- **Type:** {r.model_type_display}
- **Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Results
- **Status:** {'🚨 TROJAN DETECTED' if r.is_trojaned else '✅ CLEAN'}
- **Risk Level:** {r.risk_level.upper()}
- **Confidence:** {r.confidence:.0%}

## Probe Summary
- **Total Probes:** {r.total_probes}
- **Suspicious:** {r.suspicious_probes}

{'## Detected Credentials' + chr(10) + chr(10).join(f'- `{c}`' for c in r.detected_credentials) if r.detected_credentials else ''}

{'## Suspicious Patterns' + chr(10) + chr(10).join(f'- {p}' for p in r.detected_patterns[:5]) if r.detected_patterns else ''}

---
*Generated by Exorcist - Ghost in the Weights*
"""
        return Response(
            md,
            mimetype='text/markdown',
            headers={'Content-Disposition': f'attachment; filename="exorcist_report.md"'}
        )

    elif format == "pdf":
        try:
            pdf_content = generate_report(last_scan_result)
            return Response(
                pdf_content,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment; filename="exorcist_report.pdf"'}
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "Invalid format"}), 400


@app.route("/report/pdf", methods=["POST"])
def generate_pdf_report():
    return export_results("pdf")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "exorcist", "gpu": torch.cuda.is_available()})


@app.route("/docs")
def api_docs():
    """API documentation page."""
    return render_template("docs.html")


if __name__ == "__main__":
    print("=" * 60)
    print("  GHOST IN THE WEIGHTS")
    print("  Universal AI Model Trojan Scanner")
    print("=" * 60)
    print("\n  Open http://localhost:5000 in your browser\n")
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
