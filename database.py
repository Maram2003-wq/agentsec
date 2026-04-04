#!/usr/bin/env python3
"""
Base de données pour l'historique des scans - Version PERSISTANTE
"""

import sqlite3
import json
import os
from datetime import datetime
import pandas as pd

# Utiliser un dossier permanent dans le home
DB_DIR = os.path.join(os.path.expanduser("~"), "agentsec", "data")
DB_PATH = os.path.join(DB_DIR, "vulnscan.db")

def init_database():
    """Initialiser la base de données dans un dossier permanent"""
    # Créer le dossier permanent
    os.makedirs(DB_DIR, exist_ok=True)
    os.makedirs("/tmp/vulnscan", exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Table des scans
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE,
        target TEXT NOT NULL,
        scan_date TIMESTAMP,
        completed_at TIMESTAMP,
        status TEXT,
        security_score INTEGER,
        risk_level TEXT,
        total_findings INTEGER,
        critical INTEGER,
        high INTEGER,
        medium INTEGER,
        low INTEGER,
        info INTEGER,
        weak_credentials INTEGER,
        services_count INTEGER,
        report_path TEXT,
        raw_results TEXT
    )
    ''')
    
    # Table des daily_stats
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS daily_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date DATE UNIQUE,
        avg_score REAL,
        total_scans INTEGER,
        avg_critical REAL,
        avg_high REAL,
        avg_medium REAL,
        avg_low REAL
    )
    ''')
    
    # Table des findings individuels
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        title TEXT,
        severity TEXT,
        tool TEXT,
        description TEXT,
        remediation TEXT,
        created_at TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
    )
    ''')
    
    conn.commit()
    conn.close()
    print(f"✅ Base de données initialisée: {DB_PATH}")
    return DB_PATH

def save_scan_results(scan_data):
    """Sauvegarder les résultats d'un scan"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO scans 
        (scan_id, target, scan_date, completed_at, status, security_score, risk_level,
         total_findings, critical, high, medium, low, info, weak_credentials, services_count, report_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_data.get('scanId'),
        scan_data.get('target'),
        scan_data.get('scan_date', datetime.now().isoformat()),
        scan_data.get('completed_at', datetime.now().isoformat()),
        scan_data.get('status', 'completed'),
        scan_data.get('security_score', 0),
        scan_data.get('risk_level', 'unknown'),
        scan_data.get('total_findings', 0),
        scan_data.get('critical', 0),
        scan_data.get('high', 0),
        scan_data.get('medium', 0),
        scan_data.get('low', 0),
        scan_data.get('info', 0),
        scan_data.get('weak_credentials', 0),
        scan_data.get('services_count', 0),
        scan_data.get('report_path', '')
    ))
    
    conn.commit()
    conn.close()

def get_scan_history(limit=50):
    """Récupérer l'historique des scans"""
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(
            f"SELECT * FROM scans ORDER BY scan_date DESC LIMIT {limit}", 
            conn
        )
    except:
        df = pd.DataFrame()
    conn.close()
    return df

def get_scan_by_id(scan_id):
    """Récupérer un scan par son ID"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    row = cursor.fetchone()
    
    conn.close()
    if row:
        columns = [description[0] for description in cursor.description]
        return dict(zip(columns, row))
    return None

def get_all_scans():
    """Récupérer tous les scans"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM scans ORDER BY scan_date DESC")
    rows = cursor.fetchall()
    columns = [description[0] for description in cursor.description]
    
    conn.close()
    return [dict(zip(columns, row)) for row in rows]

def delete_scan(scan_id):
    """Supprimer un scan"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    
    conn.commit()
    conn.close()

def add_finding(scan_id, finding):
    """Ajouter un finding"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO findings (scan_id, title, severity, tool, description, remediation, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_id,
        finding.get('title'),
        finding.get('severity'),
        finding.get('tool'),
        finding.get('description'),
        finding.get('remediation'),
        datetime.now().isoformat()
    ))
    
    conn.commit()
    conn.close()

def get_statistics():
    """Obtenir les statistiques globales"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
    completed_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT SUM(total_findings) FROM scans")
    total_findings = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT SUM(critical) FROM scans")
    total_critical = cursor.fetchone()[0] or 0
    
    cursor.execute("SELECT SUM(high) FROM scans")
    total_high = cursor.fetchone()[0] or 0
    
    conn.close()
    
    return {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'total_findings': total_findings,
        'total_critical': total_critical,
        'total_high': total_high
    }

# Initialiser la base au chargement
if __name__ == "__main__":
    init_database()
    print("📊 Database module ready")
