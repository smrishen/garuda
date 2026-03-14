import sqlite3
import datetime
import os

DB_PATH = 'scamshield.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            contact TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def _normalize_contact(contact, contact_type):
    contact = contact.strip().lower()
    if contact_type == 'URL':
        # Remove common prefixes and trailing slashes
        for prefix in ['https://', 'http://', 'www.']:
            if contact.startswith(prefix):
                contact = contact[len(prefix):]
        contact = contact.rstrip('/')
    return contact


def save_report(report_data):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Normalize contact based on type
    contact_type = report_data.get('type')
    contact = _normalize_contact(report_data.get('contact', ''), contact_type)
    
    cursor.execute('''
        INSERT INTO reports (type, contact, category, description)
        VALUES (?, ?, ?, ?)
    ''', (
        report_data.get('type'),
        contact,
        report_data.get('category'),
        report_data.get('description')
    ))
    conn.commit()
    conn.close()

def search_scam(query, contact_type):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Normalize query before searching
    normalized_query = _normalize_contact(query, contact_type)

    cursor.execute('''
        SELECT type, contact, category, description, COUNT(*) as report_count 
        FROM reports 
        WHERE contact = ? AND type = ?
        GROUP BY contact
    ''', (normalized_query, contact_type))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "type": result[0],
            "contact": result[1],
            "category": result[2],
            "description": result[3],
            "reports": result[4]
        }
    return None
