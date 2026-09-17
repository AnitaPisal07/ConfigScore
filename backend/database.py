import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configscore.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            domain TEXT NOT NULL,
            score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            status_counts TEXT NOT NULL,
            scan_timestamp TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            findings_json TEXT NOT NULL,
            remediations_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_scan(
    target_url: str,
    domain: str,
    score: int,
    grade: str,
    status_counts: Dict[str, int],
    duration_ms: int,
    findings: List[Dict[str, Any]],
    remediations: List[Dict[str, Any]]
) -> int:
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.utcnow().isoformat() + "Z"
    
    cursor.execute("""
        INSERT INTO scans (
            target_url, domain, score, grade, status_counts, 
            scan_timestamp, duration_ms, findings_json, remediations_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target_url,
        domain,
        score,
        grade,
        json.dumps(status_counts),
        now_iso,
        duration_ms,
        json.dumps(findings),
        json.dumps(remediations)
    ))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit: int = 15) -> List[Dict[str, Any]]:
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, target_url, domain, score, grade, status_counts, scan_timestamp, duration_ms 
        FROM scans 
        ORDER BY id DESC 
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "target_url": r["target_url"],
            "domain": r["domain"],
            "score": r["score"],
            "grade": r["grade"],
            "status_counts": json.loads(r["status_counts"]) if r["status_counts"] else {},
            "scan_timestamp": r["scan_timestamp"],
            "duration_ms": r["duration_ms"]
        })
    return results

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    r = cursor.fetchone()
    conn.close()
    
    if not r:
        return None
        
    return {
        "id": r["id"],
        "target_url": r["target_url"],
        "domain": r["domain"],
        "score": r["score"],
        "grade": r["grade"],
        "status_counts": json.loads(r["status_counts"]) if r["status_counts"] else {},
        "scan_timestamp": r["scan_timestamp"],
        "duration_ms": r["duration_ms"],
        "findings": json.loads(r["findings_json"]) if r["findings_json"] else [],
        "remediations": json.loads(r["remediations_json"]) if r["remediations_json"] else []
    }
