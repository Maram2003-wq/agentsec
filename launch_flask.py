#!/usr/bin/env python3
"""
Lanceur Flask pour l'interface moderne de VULNSCAN
FIX: stream SSE réel via polling PDF, plus de sleep hardcodé
"""
from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_cors import CORS
import os
import glob
import json
import threading
import time
import requests as req_lib
from datetime import datetime

app = Flask(__name__, template_folder='templates')
CORS(app)

# Configuration
RESULTS_DIR = "/tmp/vulnscan"
N8N_WEBHOOK_URL = "http://localhost:5678/webhook/vulnerability-scan"
HTTP_TIMEOUT = 120       # timeout requête HTTP vers n8n
SCAN_WAIT_TIMEOUT = 600  # 10 min max pour attendre le PDF

# Dictionnaire en mémoire pour tracker les scans en cours
# { scan_id: { 'status': 'running'|'completed'|'failed', 'pdf': path, 'start': timestamp } }
SCANS = {}

os.makedirs(RESULTS_DIR, exist_ok=True)


# ==================== ROUTES PAGES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('index.html')

@app.route('/new-scan')
def new_scan():
    return render_template('index.html')

@app.route('/history')
def history():
    return render_template('index.html')


# ==================== API STATS ====================

@app.route('/api/stats')
def api_stats():
    try:
        # Lire tous les PDFs existants dans /tmp/vulnscan/
        pdfs = glob.glob(f"{RESULTS_DIR}/*.pdf")
        pdfs.sort(key=os.path.getmtime, reverse=True)
        total_scans = len(pdfs)

        recent_scans = []
        for i, pdf in enumerate(pdfs[:5]):
            fname = os.path.basename(pdf)
            recent_scans.append({
                'id': fname.replace('.pdf', ''),
                'target': 'scanme.nmap.org',
                'status': 'completed',
                'created_at': datetime.fromtimestamp(os.path.getmtime(pdf)).isoformat(),
                'finished_at': datetime.fromtimestamp(os.path.getmtime(pdf)).isoformat()
            })

        # Ajouter les scans en cours (en mémoire)
        running = sum(1 for s in SCANS.values() if s['status'] == 'running')

        return jsonify({
            'totals': {
                'total_scans': total_scans + len(SCANS),
                'running_scans': running,
                'total_findings': total_scans,
                'total_cves': total_scans,
                'completed_scans': total_scans
            },
            'severity_breakdown': [
                {'severity': 'critical', 'count': 1},
                {'severity': 'high', 'count': 2},
                {'severity': 'medium', 'count': 3},
                {'severity': 'low', 'count': 5},
                {'severity': 'info', 'count': 10}
            ],
            'recent_scans': recent_scans,
            'critical_findings': []
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== API SCANS ====================

@app.route('/api/scans', methods=['GET'])
def api_scans():
    try:
        pdfs = glob.glob(f"{RESULTS_DIR}/*.pdf")
        pdfs.sort(key=os.path.getmtime, reverse=True)
        scans = []

        for pdf in pdfs[:50]:
            fname = os.path.basename(pdf)
            scans.append({
                'id': fname.replace('.pdf', ''),
                'target': 'scanme.nmap.org',
                'status': 'completed',
                'port_range': '1-1000',
                'created_at': datetime.fromtimestamp(os.path.getmtime(pdf)).isoformat(),
                'finished_at': datetime.fromtimestamp(os.path.getmtime(pdf)).isoformat(),
                'findings_count': 1,
                'cves_count': 1
            })

        # Ajouter les scans en cours depuis la mémoire
        for scan_id, info in SCANS.items():
            if info['status'] == 'running':
                scans.insert(0, {
                    'id': scan_id,
                    'target': info.get('target', '?'),
                    'status': 'running',
                    'port_range': info.get('port_range', '1-1000'),
                    'created_at': datetime.fromtimestamp(info['start']).isoformat(),
                    'finished_at': None,
                    'findings_count': 0,
                    'cves_count': 0
                })

        return jsonify({'scans': scans, 'total': len(scans)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans', methods=['POST'])
def api_create_scan():
    try:
        data = request.json
        target = data.get('target')
        port_range = data.get('port_range', '1-1000')
        email_to = data.get('email_to', 'scan@local')

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        start_time = time.time()

        # Enregistrer en mémoire
        SCANS[scan_id] = {
            'status': 'running',
            'target': target,
            'port_range': port_range,
            'start': start_time,
            'pdf': None
        }

        # Lancer n8n + attendre le PDF en arrière-plan
        threading.Thread(
            target=run_scan_background,
            args=(scan_id, target, port_range, email_to, start_time),
            daemon=True
        ).start()

        return jsonify({'id': scan_id, 'status': 'running'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== CORE FIX : POLLING PDF PAR TIMESTAMP ====================

def run_scan_background(scan_id, target, port_range, email_to, start_time):
    """
    Lance n8n et attend le PDF.
    FIX: cherche TOUT pdf créé après start_time (pas de matching par nom).
    n8n génère des noms comme 2026-04-04T19-46-23.pdf — pas notre scan_id.
    """
    try:
        payload = {
            "network": target,
            "email": email_to,
            "portRange": port_range
        }

        try:
            req_lib.post(N8N_WEBHOOK_URL, json=payload, timeout=HTTP_TIMEOUT)
            print(f"✅ Scan {scan_id} déclenché sur {target}")
        except req_lib.exceptions.ReadTimeout:
            # Normal pour les scans longs — n8n a bien reçu
            print(f"⏰ Scan {scan_id} déclenché (timeout HTTP normal)")
        except Exception as e:
            print(f"❌ Erreur déclenchement {scan_id}: {e}")
            SCANS[scan_id]['status'] = 'failed'
            return

        print(f"⏳ Attente PDF pour scan {scan_id} (max {SCAN_WAIT_TIMEOUT}s)...")

        while time.time() - start_time < SCAN_WAIT_TIMEOUT:
            # Chercher N'IMPORTE QUEL PDF créé après le début du scan
            pdfs = glob.glob(f"{RESULTS_DIR}/*.pdf")
            for pdf in pdfs:
                if os.path.getmtime(pdf) >= start_time:
                    # PDF trouvé !
                    SCANS[scan_id]['status'] = 'completed'
                    SCANS[scan_id]['pdf'] = pdf
                    print(f"✅ Scan {scan_id} terminé → {os.path.basename(pdf)}")
                    return

            time.sleep(5)

        # Timeout
        print(f"⏰ Scan {scan_id} timeout après {SCAN_WAIT_TIMEOUT}s")
        SCANS[scan_id]['status'] = 'failed'

    except Exception as e:
        print(f"❌ Erreur scan {scan_id}: {e}")
        SCANS[scan_id]['status'] = 'failed'


# ==================== CORE FIX : STREAM SSE RÉEL ====================

@app.route('/api/scans/<scan_id>/stream')
def api_scan_stream(scan_id):
    """
    Server-Sent Events — suit la progression réelle du scan.
    FIX: poll SCANS[] en mémoire toutes les 5s.
    Plus de sleep hardcodé — 'completed' est envoyé SEULEMENT
    quand run_scan_background a trouvé le vrai PDF.
    """
    def generate():
        yield f"data: {json.dumps({'type': 'scan_started'})}\n\n"

        start_time = time.time()

        while time.time() - start_time < SCAN_WAIT_TIMEOUT:
            scan_info = SCANS.get(scan_id)

            if scan_info:
                status = scan_info['status']

                if status == 'completed':
                    pdf = scan_info.get('pdf', '')
                    pdf_name = os.path.basename(pdf) if pdf else ''
                    elapsed = int(time.time() - scan_info['start'])
                    yield f"data: {json.dumps({'type': 'scan_completed', 'pdf': pdf_name, 'elapsed': elapsed})}\n\n"
                    return

                if status == 'failed':
                    yield f"data: {json.dumps({'type': 'scan_error', 'message': 'Scan failed'})}\n\n"
                    return

            # Heartbeat toutes les 5s pour garder la connexion active
            elapsed = int(time.time() - start_time)
            yield f"data: {json.dumps({'type': 'heartbeat', 'elapsed': elapsed})}\n\n"
            time.sleep(5)

        yield f"data: {json.dumps({'type': 'scan_error', 'message': 'Timeout'})}\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


# ==================== AUTRES ROUTES ====================

@app.route('/api/scans/<scan_id>', methods=['GET'])
def api_get_scan(scan_id):
    try:
        # Chercher dans les scans en mémoire d'abord
        scan_info = SCANS.get(scan_id)
        pdf_path = scan_info['pdf'] if scan_info and scan_info.get('pdf') else None

        # Fallback: chercher PDF dans /tmp/vulnscan/
        if not pdf_path:
            pdfs = glob.glob(f"{RESULTS_DIR}/*.pdf")
            for pdf in pdfs:
                if scan_id in os.path.basename(pdf):
                    pdf_path = pdf
                    break

        status = scan_info['status'] if scan_info else ('completed' if pdf_path else 'unknown')

        return jsonify({
            'scan': {
                'id': scan_id,
                'target': scan_info['target'] if scan_info else 'unknown',
                'status': status,
                'port_range': scan_info['port_range'] if scan_info else '1-1000',
                'created_at': datetime.fromtimestamp(scan_info['start']).isoformat() if scan_info else datetime.now().isoformat(),
                'finished_at': datetime.now().isoformat() if status == 'completed' else None
            },
            'findings': [],
            'services': [],
            'cves': [],
            'severity_counts': [],
            'ai_analysis': None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    try:
        # Supprimer de la mémoire
        SCANS.pop(scan_id, None)
        # Supprimer le PDF si trouvé
        pdfs = glob.glob(f"{RESULTS_DIR}/*.pdf")
        for pdf in pdfs:
            if scan_id in os.path.basename(pdf):
                os.remove(pdf)
        return jsonify({'status': 'deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/<scan_id>/report', methods=['GET'])
def api_get_report(scan_id):
    """
    FIX: cherche d'abord le PDF lié au scan en mémoire,
    puis fallback sur le PDF le plus récent.
    """
    try:
        # 1. PDF lié au scan en mémoire
        scan_info = SCANS.get(scan_id)
        if scan_info and scan_info.get('pdf') and os.path.exists(scan_info['pdf']):
            return send_file(scan_info['pdf'], as_attachment=True,
                             download_name=f"report_{scan_id}.pdf")

        # 2. PDF dont le nom contient le scan_id
        pdfs = glob.glob(f"{RESULTS_DIR}/*.pdf")
        for pdf in pdfs:
            if scan_id in os.path.basename(pdf):
                return send_file(pdf, as_attachment=True,
                                 download_name=f"report_{scan_id}.pdf")

        # 3. Fallback: PDF le plus récent
        if pdfs:
            latest = max(pdfs, key=os.path.getmtime)
            return send_file(latest, as_attachment=True,
                             download_name=f"report_{scan_id}.pdf")

        return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== LANCEMENT ====================

if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("🚀 VULNSCAN - Interface Moderne")
    print("=" * 50)
    print(f"📱 Interface : http://localhost:3000")
    print(f"📊 API       : http://localhost:3000/api/stats")
    print(f"📁 PDFs      : {RESULTS_DIR}/")
    print(f"⏰ Timeout   : HTTP {HTTP_TIMEOUT}s | Scan {SCAN_WAIT_TIMEOUT}s")
    print("=" * 50 + "\n")
    app.run(host='0.0.0.0', port=3000, debug=False)
