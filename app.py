#!/usr/bin/env python3
"""
AgentSec - Scanner de Vulnérabilités
Interface Flask pure (sans Streamlit)
Fix: PDF detection par timestamp, stream SSE via DB
"""

import os
import glob
import json
import time
import queue
import threading
import requests
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response, send_file
from flask_cors import CORS
from database import *

# ==================== CONFIGURATION ====================
N8N_WEBHOOK_URL = "http://localhost:5678/webhook/vulnerability-scan"
RESULTS_DIR = "/tmp/vulnscan"
SCAN_STATUS = {}
SCAN_QUEUE = queue.Queue()
HTTP_TIMEOUT = 120
SCAN_WAIT_TIMEOUT = 600  # 10 minutes max

# ==================== FLASK APP ====================
app = Flask(__name__, template_folder='templates')
CORS(app)

os.makedirs('templates', exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)


# ==================== ROUTES PAGES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('index.html')

@app.route('/new-scan')
def new_scan_page():
    return render_template('index.html')

@app.route('/history')
def history():
    return render_template('index.html')


# ==================== API STATS ====================

@app.route('/api/stats', methods=['GET'])
def api_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'")
        running_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
        completed_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM findings")
        total_findings = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM cves")
        total_cves = cursor.fetchone()[0]

        cursor.execute("""
            SELECT severity, COUNT(*) FROM findings
            WHERE severity IS NOT NULL GROUP BY severity
        """)
        severity_breakdown = [{'severity': r[0], 'count': r[1]} for r in cursor.fetchall()]

        cursor.execute("""
            SELECT id, target, status, created_at, finished_at
            FROM scans ORDER BY created_at DESC LIMIT 5
        """)
        recent_scans = [
            {'id': r[0], 'target': r[1], 'status': r[2],
             'created_at': r[3], 'finished_at': r[4]}
            for r in cursor.fetchall()
        ]

        cursor.execute("""
            SELECT f.id, f.title, f.severity, f.tool, f.host, s.target
            FROM findings f LEFT JOIN scans s ON f.scan_id = s.id
            WHERE f.severity IN ('critical', 'high')
            ORDER BY f.created_at DESC LIMIT 10
        """)
        critical_findings = [
            {'id': r[0], 'title': r[1], 'severity': r[2],
             'tool': r[3], 'host': r[4], 'target': r[5], 'scan_id': r[0]}
            for r in cursor.fetchall()
        ]

        conn.close()
        return jsonify({
            'totals': {
                'total_scans': total_scans,
                'running_scans': running_scans,
                'total_findings': total_findings,
                'total_cves': total_cves,
                'completed_scans': completed_scans
            },
            'severity_breakdown': severity_breakdown,
            'recent_scans': recent_scans,
            'critical_findings': critical_findings
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== API SCANS ====================

@app.route('/api/scans', methods=['GET'])
def api_scans():
    try:
        limit = request.args.get('limit', 50)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target, status, port_range, created_at, finished_at,
                   (SELECT COUNT(*) FROM findings WHERE scan_id = scans.id) as findings_count,
                   (SELECT COUNT(*) FROM cves WHERE scan_id = scans.id) as cves_count
            FROM scans ORDER BY created_at DESC LIMIT ?
        """, (limit,))
        scans = [
            {'id': r[0], 'target': r[1], 'status': r[2], 'port_range': r[3],
             'created_at': r[4], 'finished_at': r[5],
             'findings_count': r[6], 'cves_count': r[7]}
            for r in cursor.fetchall()
        ]
        cursor.execute("SELECT COUNT(*) FROM scans")
        total = cursor.fetchone()[0]
        conn.close()
        return jsonify({'scans': scans, 'total': total})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans', methods=['POST'])
def api_create_scan():
    try:
        data = request.json
        target = data.get('target')
        port_range = data.get('port_range', '1-1000')
        email_to = data.get('email_to')

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (id, target, port_range, status, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, target, port_range, 'running', datetime.now().isoformat()))
        conn.commit()
        conn.close()

        threading.Thread(
            target=run_scan_background,
            args=(scan_id, target, port_range, email_to),
            daemon=True
        ).start()

        return jsonify({'id': scan_id, 'status': 'running'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== FIX PRINCIPAL : DETECTION PDF PAR TIMESTAMP ====================

def run_scan_background(scan_id, target, port_range, email_to):
    """
    Lance le scan n8n et attend le PDF.
    FIX: on cherche TOUT pdf créé après le début du scan,
    sans essayer de matcher le scan_id dans le nom du fichier.
    (n8n génère ex: 2026-04-04T18-28-47.pdf, pas notre scan_id)
    """
    start_time = time.time()

    try:
        payload = {"network": target, "email": email_to, "portRange": port_range}

        try:
            requests.post(N8N_WEBHOOK_URL, json=payload, timeout=HTTP_TIMEOUT)
            print(f"✅ Scan {scan_id} déclenché sur {target}")
        except requests.exceptions.ReadTimeout:
            # Normal pour les scans longs — n8n a bien reçu la requête
            print(f"⏰ Scan {scan_id} déclenché (timeout HTTP normal)")
        except Exception as e:
            print(f"❌ Erreur déclenchement scan {scan_id}: {e}")
            update_scan_status(scan_id, 'failed')
            return

        # Attendre le PDF généré par n8n
        # On cherche n'importe quel PDF récent dans /tmp/vulnscan/
        # créé APRÈS le début de ce scan (évite de matcher d'anciens PDFs)
        print(f"⏳ Attente du PDF pour scan {scan_id}...")

        while time.time() - start_time < SCAN_WAIT_TIMEOUT:
            pdfs = glob.glob(f"{RESULTS_DIR}/*.pdf")
            for pdf in pdfs:
                mtime = os.path.getmtime(pdf)
                if mtime >= start_time:
                    # PDF trouvé créé après le début du scan
                    update_scan_status(scan_id, 'completed', pdf)
                    print(f"✅ Scan {scan_id} terminé → {os.path.basename(pdf)}")
                    return
            time.sleep(5)

        # Timeout dépassé
        print(f"⏰ Scan {scan_id} timeout après {SCAN_WAIT_TIMEOUT}s")
        update_scan_status(scan_id, 'failed')

    except Exception as e:
        print(f"❌ Erreur scan {scan_id}: {e}")
        update_scan_status(scan_id, 'failed')


def update_scan_status(scan_id, status, report_path=None):
    """Mettre à jour le statut d'un scan dans la DB"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE scans
            SET status = ?, finished_at = ?, report_path = ?
            WHERE id = ?
        """, (status, datetime.now().isoformat(), report_path, scan_id))
        conn.commit()
        conn.close()
        SCAN_STATUS[scan_id] = {'status': status, 'pdf_path': report_path}
        print(f"📝 Scan {scan_id} → {status}" + (f" ({os.path.basename(report_path)})" if report_path else ""))
    except Exception as e:
        print(f"❌ Erreur mise à jour statut: {e}")


# ==================== API SCAN DETAIL ====================

@app.route('/api/scans/<scan_id>', methods=['GET'])
def api_get_scan(scan_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, target, status, port_range, created_at, finished_at
            FROM scans WHERE id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Scan not found'}), 404

        scan = {
            'id': row[0], 'target': row[1], 'status': row[2],
            'port_range': row[3], 'created_at': row[4], 'finished_at': row[5]
        }

        cursor.execute("""
            SELECT title, description, severity, tool, evidence, remediation, host, port
            FROM findings WHERE scan_id = ?
        """, (scan_id,))
        findings = [
            {'title': r[0], 'description': r[1], 'severity': r[2], 'tool': r[3],
             'evidence': r[4], 'remediation': r[5], 'host': r[6], 'port': r[7]}
            for r in cursor.fetchall()
        ]

        cursor.execute("""
            SELECT port, protocol, name, product, version, cpe
            FROM services WHERE scan_id = ?
        """, (scan_id,))
        services = [
            {'port': r[0], 'protocol': r[1], 'name': r[2],
             'product': r[3], 'version': r[4], 'cpe': r[5]}
            for r in cursor.fetchall()
        ]

        cursor.execute("""
            SELECT id, description, cvss_score, cvss_severity
            FROM cves WHERE scan_id = ?
        """, (scan_id,))
        cves = [
            {'id': r[0], 'description': r[1],
             'cvss_score': r[2], 'cvss_severity': r[3]}
            for r in cursor.fetchall()
        ]

        cursor.execute("""
            SELECT severity, COUNT(*) FROM findings
            WHERE scan_id = ? GROUP BY severity
        """, (scan_id,))
        severity_counts = [{'severity': r[0], 'count': r[1]} for r in cursor.fetchall()]

        conn.close()
        return jsonify({
            'scan': scan,
            'findings': findings,
            'services': services,
            'cves': cves,
            'severity_counts': severity_counts,
            'ai_analysis': None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        for table in ['findings', 'services', 'cves']:
            cursor.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== RAPPORT PDF ====================

@app.route('/api/scans/<scan_id>/report', methods=['GET'])
def api_get_report(scan_id):
    """
    Télécharger le rapport PDF.
    FIX: on cherche le report_path stocké en DB,
    puis fallback sur le PDF le plus récent dans /tmp/vulnscan/
    """
    try:
        # 1. Chercher le chemin stocké en DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT report_path FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        if row and row[0] and os.path.exists(row[0]):
            return send_file(row[0], as_attachment=True,
                             download_name=f"report_{scan_id}.pdf")

        # 2. Fallback: chercher n'importe quel PDF dans /tmp/vulnscan/
        pdfs = glob.glob(f"{RESULTS_DIR}/*.pdf")
        if pdfs:
            latest = max(pdfs, key=os.path.getmtime)
            return send_file(latest, as_attachment=True,
                             download_name=f"report_{scan_id}.pdf")

        return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== FIX STREAM SSE : POLLING DB ====================

@app.route('/api/scans/<scan_id>/stream')
def api_scan_stream(scan_id):
    """
    Server-Sent Events pour suivre la progression.
    FIX: on poll la DB toutes les 5s au lieu de chercher le PDF directement.
    L'interface reçoit 'scan_completed' dès que run_scan_background
    a mis à jour le statut en DB → synchronisation parfaite.
    """
    def generate():
        yield f"data: {json.dumps({'type': 'scan_started'})}\n\n"
        start_time = time.time()

        while time.time() - start_time < SCAN_WAIT_TIMEOUT:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT status, report_path FROM scans WHERE id = ?",
                    (scan_id,)
                )
                row = cursor.fetchone()
                conn.close()

                if row:
                    status = row[0]
                    report_path = row[1]

                    if status == 'completed':
                        pdf_name = os.path.basename(report_path) if report_path else ''
                        yield f"data: {json.dumps({'type': 'scan_completed', 'pdf': pdf_name})}\n\n"
                        return

                    if status == 'failed':
                        yield f"data: {json.dumps({'type': 'scan_error', 'message': 'Scan failed'})}\n\n"
                        return

            except Exception as e:
                print(f"❌ Stream error: {e}")

            # Envoyer un heartbeat pour garder la connexion active
            elapsed = int(time.time() - start_time)
            yield f"data: {json.dumps({'type': 'heartbeat', 'elapsed': elapsed})}\n\n"
            time.sleep(5)

        yield f"data: {json.dumps({'type': 'scan_error', 'message': 'Timeout'})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ==================== ROUTE CALLBACK N8N (BONUS) ====================

@app.route('/api/scans/<scan_id>/complete', methods=['POST'])
def api_scan_complete(scan_id):
    """
    Route optionnelle : n8n peut appeler cette URL à la fin du workflow
    pour notifier Flask immédiatement sans attendre le polling.
    Dans n8n : ajouter un nœud HTTP Request pointant vers
    http://localhost:3000/api/scans/{scanId}/complete
    avec body: { "report_path": "/tmp/vulnscan/xxx.pdf" }
    """
    try:
        data = request.json or {}
        report_path = data.get('report_path', '')
        update_scan_status(scan_id, 'completed', report_path)
        print(f"🔔 n8n callback reçu pour scan {scan_id}")
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== LANCEMENT ====================

if __name__ == '__main__':
    print("\n" + "=" * 55)
    print("🚀 AgentSec - Scanner de Vulnérabilités (Flask)")
    print("=" * 55)
    print(f"📱 Interface : http://localhost:3000")
    print(f"📊 API stats : http://localhost:3000/api/stats")
    print(f"⚙️  n8n       : http://localhost:5678")
    print(f"⏰ Timeout   : HTTP {HTTP_TIMEOUT}s | Scan {SCAN_WAIT_TIMEOUT}s")
    print(f"📁 PDFs      : {RESULTS_DIR}/")
    print("=" * 55 + "\n")
    app.run(host='0.0.0.0', port=3000, debug=False)
