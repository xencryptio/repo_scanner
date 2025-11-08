"""
Enhanced GitHub Repository Cryptographic Algorithm Scanner
With SQLite caching, hash-based deduplication, job queue, and REST API
"""

import re
import os
import sys
import json
import tempfile
import subprocess
import sqlite3
import hashlib
import threading 
import shutil 
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Set, Optional
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# Complete cryptographic patterns from original script
CRYPTO_PATTERNS = {
    # Symmetric algorithms (PQC Safe)
    'AES': {
        'patterns': [r'\bAES\b', r'\baes[-_]?(128|192|256)\b', r'AES_', r'Cipher\.AES', r'EVP_aes'],
        'pqc_safe': True,
        'category': 'Symmetric Encryption'
    },
    'ChaCha20': {
        'patterns': [r'\bChaCha20\b', r'\bchacha20\b', r'CHACHA20', r'EVP_chacha'],
        'pqc_safe': True,
        'category': 'Symmetric Encryption'
    },
    'ChaCha20-Poly1305': {
        'patterns': [r'\bChaCha20[-_]?Poly1305\b', r'chacha20[-_]poly1305', r'CHACHA20_POLY1305'],
        'pqc_safe': True,
        'category': 'Authenticated Encryption'
    },
    'Salsa20': {
        'patterns': [r'\bSalsa20\b', r'\bsalsa20\b'],
        'pqc_safe': True,
        'category': 'Symmetric Encryption'
    },
    'Twofish': {
        'patterns': [r'\bTwofish\b', r'\btwofish\b'],
        'pqc_safe': True,
        'category': 'Symmetric Encryption'
    },
    'Blowfish': {
        'patterns': [r'\bBlowfish\b', r'\bblowfish\b', r'BF_'],
        'pqc_safe': True,
        'category': 'Symmetric Encryption'
    },
    'Camellia': {
        'patterns': [r'\bCamellia\b', r'\bcamellia\b'],
        'pqc_safe': True,
        'category': 'Symmetric Encryption'
    },
    'ARIA': {
        'patterns': [r'\bARIA\b(?!-)'],
        'pqc_safe': True,
        'category': 'Symmetric Encryption'
    },
    '3DES': {
        'patterns': [r'\b3DES\b', r'\bDES3\b', r'\bTripleDES\b', r'DES_EDE', r'EVP_des_ede'],
        'pqc_safe': True,
        'category': 'Symmetric Encryption (Weak)'
    },
    'DES': {
        'patterns': [r'\bDES\b(?!3|_EDE|C)', r'DES_encrypt', r'EVP_des_'],
        'pqc_safe': True,
        'category': 'Symmetric Encryption (Broken)'
    },
    'RC4': {
        'patterns': [r'\bRC4\b', r'\brc4\b', r'ARC4', r'ARCFOUR'],
        'pqc_safe': True,
        'category': 'Stream Cipher (Broken)'
    },
    
    # Block cipher modes
    'GCM': {
        'patterns': [r'\bGCM\b', r'\bgcm\b', r'Galois.*Counter', r'AES.*GCM'],
        'pqc_safe': True,
        'category': 'Cipher Mode (AEAD)'
    },
    'CBC': {
        'patterns': [r'\bCBC\b', r'\bcbc\b', r'Cipher.*Block.*Chaining'],
        'pqc_safe': True,
        'category': 'Cipher Mode'
    },
    'CTR': {
        'patterns': [r'\bCTR\b(?!L)', r'\bctr\b', r'Counter.*Mode'],
        'pqc_safe': True,
        'category': 'Cipher Mode'
    },
    'CCM': {
        'patterns': [r'\bCCM\b', r'\bccm\b', r'Counter.*CBC.*MAC'],
        'pqc_safe': True,
        'category': 'Cipher Mode (AEAD)'
    },
    'ECB': {
        'patterns': [r'\bECB\b', r'\becb\b', r'Electronic.*Codebook'],
        'pqc_safe': True,
        'category': 'Cipher Mode (Insecure)'
    },
    
    # Hash functions (PQC Safe)
    'SHA-256': {
        'patterns': [r'\bSHA256\b', r'\bsha256\b', r'SHA-256', r'sha_256', r'EVP_sha256'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'SHA-384': {
        'patterns': [r'\bSHA384\b', r'\bsha384\b', r'SHA-384', r'EVP_sha384'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'SHA-512': {
        'patterns': [r'\bSHA512\b', r'\bsha512\b', r'SHA-512', r'EVP_sha512'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'SHA-224': {
        'patterns': [r'\bSHA224\b', r'\bsha224\b', r'SHA-224'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'SHA3-256': {
        'patterns': [r'\bSHA3[-_]256\b', r'\bsha3[-_]256\b'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'SHA3-384': {
        'patterns': [r'\bSHA3[-_]384\b', r'\bsha3[-_]384\b'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'SHA3-512': {
        'patterns': [r'\bSHA3[-_]512\b', r'\bsha3[-_]512\b'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'BLAKE2': {
        'patterns': [r'\bBLAKE2\b', r'\bblake2[bs]\b', r'BLAKE2b', r'BLAKE2s'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'BLAKE3': {
        'patterns': [r'\bBLAKE3\b', r'\bblake3\b'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'Keccak': {
        'patterns': [r'\bKeccak\b', r'\bkeccak\b'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'RIPEMD-160': {
        'patterns': [r'\bRIPEMD[-_]?160\b', r'\bripemd160\b'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'Whirlpool': {
        'patterns': [r'\bWhirlpool\b', r'\bwhirlpool\b'],
        'pqc_safe': True,
        'category': 'Hash Function'
    },
    'MD5': {
        'patterns': [r'\bMD5\b', r'\bmd5\b', r'EVP_md5'],
        'pqc_safe': True,
        'category': 'Hash Function (Broken)'
    },
    'MD4': {
        'patterns': [r'\bMD4\b', r'\bmd4\b'],
        'pqc_safe': True,
        'category': 'Hash Function (Broken)'
    },
    'SHA-1': {
        'patterns': [r'\bSHA1\b', r'\bsha1\b', r'SHA-1', r'EVP_sha1'],
        'pqc_safe': True,
        'category': 'Hash Function (Weak)'
    },
    
    # MAC algorithms
    'HMAC': {
        'patterns': [r'\bHMAC\b', r'\bhmac\b', r'HMAC_'],
        'pqc_safe': True,
        'category': 'Message Authentication Code'
    },
    'CMAC': {
        'patterns': [r'\bCMAC\b', r'\bcmac\b'],
        'pqc_safe': True,
        'category': 'Message Authentication Code'
    },
    'Poly1305': {
        'patterns': [r'\bPoly1305\b', r'\bpoly1305\b'],
        'pqc_safe': True,
        'category': 'Message Authentication Code'
    },
    
    # Key derivation functions
    'PBKDF2': {
        'patterns': [r'\bPBKDF2\b', r'\bpbkdf2\b'],
        'pqc_safe': True,
        'category': 'Key Derivation Function'
    },
    'scrypt': {
        'patterns': [r'\bscrypt\b', r'\bSCRYPT\b'],
        'pqc_safe': True,
        'category': 'Key Derivation Function'
    },
    'Argon2': {
        'patterns': [r'\bArgon2\b', r'\bargon2[id]?\b'],
        'pqc_safe': True,
        'category': 'Key Derivation Function'
    },
    'bcrypt': {
        'patterns': [r'\bbcrypt\b', r'\bBCRYPT\b'],
        'pqc_safe': True,
        'category': 'Password Hashing'
    },
    'HKDF': {
        'patterns': [r'\bHKDF\b', r'\bhkdf\b'],
        'pqc_safe': True,
        'category': 'Key Derivation Function'
    },
    
    # Asymmetric algorithms (NOT PQC Safe)
    'RSA': {
        'patterns': [r'\bRSA\b', r'\brsa[-_]?(1024|2048|3072|4096)\b', r'RSA_', r'PKCS1', r'EVP_PKEY_RSA'],
        'pqc_safe': False,
        'category': 'Asymmetric Encryption'
    },
    'ECDSA': {
        'patterns': [r'\bECDSA\b', r'\becdsa\b', r'EC_DSA', r'secp256[kr]1', r'prime256v1'],
        'pqc_safe': False,
        'category': 'Digital Signature'
    },
    'ECDH': {
        'patterns': [r'\bECDH\b', r'\becdh\b', r'EC_DH', r'ECDHE'],
        'pqc_safe': False,
        'category': 'Key Exchange'
    },
    'DSA': {
        'patterns': [r'\bDSA\b(?!A)', r'DSA_', r'Digital Signature Algorithm'],
        'pqc_safe': False,
        'category': 'Digital Signature'
    },
    'DH': {
        'patterns': [r'\bDiffie[-_]?Hellman\b', r'\bDH\b', r'DHE', r'EVP_PKEY_DH'],
        'pqc_safe': False,
        'category': 'Key Exchange'
    },
    'ElGamal': {
        'patterns': [r'\bElGamal\b', r'\belgamal\b'],
        'pqc_safe': False,
        'category': 'Asymmetric Encryption'
    },
    'Ed25519': {
        'patterns': [r'\bEd25519\b', r'\bed25519\b', r'EdDSA'],
        'pqc_safe': False,
        'category': 'Digital Signature'
    },
    'Ed448': {
        'patterns': [r'\bEd448\b', r'\bed448\b'],
        'pqc_safe': False,
        'category': 'Digital Signature'
    },
    'Curve25519': {
        'patterns': [r'\bCurve25519\b', r'\bcurve25519\b', r'X25519'],
        'pqc_safe': False,
        'category': 'Key Exchange'
    },
    'Curve448': {
        'patterns': [r'\bCurve448\b', r'\bcurve448\b', r'X448'],
        'pqc_safe': False,
        'category': 'Key Exchange'
    },
    'P-256': {
        'patterns': [r'\bP-256\b', r'\bsecp256r1\b', r'prime256v1'],
        'pqc_safe': False,
        'category': 'Elliptic Curve'
    },
    'P-384': {
        'patterns': [r'\bP-384\b', r'\bsecp384r1\b'],
        'pqc_safe': False,
        'category': 'Elliptic Curve'
    },
    'P-521': {
        'patterns': [r'\bP-521\b', r'\bsecp521r1\b'],
        'pqc_safe': False,
        'category': 'Elliptic Curve'
    },
    'secp256k1': {
        'patterns': [r'\bsecp256k1\b'],
        'pqc_safe': False,
        'category': 'Elliptic Curve (Bitcoin)'
    },
    
    # PQC algorithms (PQC Safe)
    'Kyber': {
        'patterns': [r'\bKyber\b', r'\bkyber\b', r'ML-KEM', r'CRYSTALS-Kyber'],
        'pqc_safe': True,
        'category': 'PQC Key Encapsulation'
    },
    'Dilithium': {
        'patterns': [r'\bDilithium\b', r'\bdilithium\b', r'ML-DSA', r'CRYSTALS-Dilithium'],
        'pqc_safe': True,
        'category': 'PQC Digital Signature'
    },
    'SPHINCS+': {
        'patterns': [r'\bSPHINCS\+?\b', r'\bsphincs\b', r'SLH-DSA'],
        'pqc_safe': True,
        'category': 'PQC Digital Signature'
    },
    'NTRU': {
        'patterns': [r'\bNTRU\b', r'\bntru\b', r'NTRUEncrypt'],
        'pqc_safe': True,
        'category': 'PQC Encryption'
    },
    'Falcon': {
        'patterns': [r'\bFalcon\b(?!.*[Bb]ird)', r'\bfalcon\b(?!.*bird)'],
        'pqc_safe': True,
        'category': 'PQC Digital Signature'
    },
    'SABER': {
        'patterns': [r'\bSABER\b', r'\bSaber\b(?!tooth)'],
        'pqc_safe': True,
        'category': 'PQC Key Encapsulation'
    },
    'FrodoKEM': {
        'patterns': [r'\bFrodoKEM\b', r'\bFrodo\b'],
        'pqc_safe': True,
        'category': 'PQC Key Encapsulation'
    },
    'BIKE': {
        'patterns': [r'\bBIKE\b(?!-)'],
        'pqc_safe': True,
        'category': 'PQC Key Encapsulation'
    },
    'HQC': {
        'patterns': [r'\bHQC\b'],
        'pqc_safe': True,
        'category': 'PQC Key Encapsulation'
    },
    'Rainbow': {
        'patterns': [r'\bRainbow\b(?!.*color)'],
        'pqc_safe': True,
        'category': 'PQC Digital Signature (Broken)'
    },
    'XMSS': {
        'patterns': [r'\bXMSS\b', r'\bxmss\b'],
        'pqc_safe': True,
        'category': 'PQC Digital Signature'
    },
    'LMS': {
        'patterns': [r'\bLMS\b(?!-)'],
        'pqc_safe': True,
        'category': 'PQC Digital Signature'
    },
}

CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h', '.hpp', 
    '.cs', '.go', '.rs', '.rb', '.php', '.swift', '.kt', '.scala', '.sh', 
    '.bash', '.zsh', '.pl', '.lua', '.r', '.m', '.mm', '.dart', '.groovy',
    '.clj', '.ex', '.exs', '.erl', '.hrl', '.ml', '.fs', '.vb', '.pas',
    '.html', '.htm', '.css', '.scss', '.sass', '.less', '.vue', '.svelte',
    '.yaml', '.yml', '.json', '.toml', '.xml', '.ini', '.conf', '.config',
    '.properties', '.env', '.gradle', '.cmake', '.make', '.mk', '.dockerfile', 
    '.md', '.rst', '.txt', '.asciidoc', '.asm', '.s', '.sql', '.proto', 
    '.thrift', '.graphql'
}


class Database:
    """SQLite database manager for scan results with job queue"""
    
    def __init__(self, db_path='crypto_scans.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema with job queue support"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # --- FIX APPLIED HERE ---
        # The column existence checks are removed because the columns 
        # (current_status, total_files_to_scan, created_at) 
        # are already included in the CREATE TABLE statement below.
        # This prevents the 'duplicate column name' error on first run.
        
        # Create repositories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS repositories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_url TEXT UNIQUE NOT NULL,
                repo_hash TEXT NOT NULL,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_status TEXT DEFAULT 'pending',
                total_files INTEGER DEFAULT 0,
                total_algorithms INTEGER DEFAULT 0,
                pqc_safe_count INTEGER DEFAULT 0,
                pqc_vulnerable_count INTEGER DEFAULT 0,
                current_status TEXT DEFAULT 'Queued for scanning',
                total_files_to_scan INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # To support future schema changes, you can re-enable the column check, 
        # but only for columns *not* already in the CREATE TABLE block above.
        
        # # Check existing columns (only if needed for columns NOT in CREATE TABLE)
        # cursor.execute("PRAGMA table_info(repositories)")
        # columns = [col[1] for col in cursor.fetchall()]

        # # Example of how to add a NEW column (e.g., 'scan_version') if needed later:
        # if 'scan_version' not in columns:
        #     cursor.execute('ALTER TABLE repositories ADD COLUMN scan_version INTEGER DEFAULT 1')


        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_id INTEGER NOT NULL,
                algorithm TEXT NOT NULL,
                category TEXT NOT NULL,
                is_pqc_safe BOOLEAN NOT NULL,
                occurrences INTEGER NOT NULL,
                files_affected INTEGER NOT NULL,
                FOREIGN KEY (repo_id) REFERENCES repositories(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_result_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                context TEXT,
                match_text TEXT,
                FOREIGN KEY (scan_result_id) REFERENCES scan_results(id)
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_repo_hash ON repositories(repo_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_repo_url ON repositories(repo_url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_status ON repositories(scan_status)')
        
        conn.commit()
        conn.close()
    
    def get_cached_scan(self, repo_hash: str) -> Optional[Dict]:
        """Check if completed scan exists for this repo hash"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, repo_url, last_scanned, scan_status, 
                   total_files, total_algorithms, pqc_safe_count, pqc_vulnerable_count,
                   current_status, total_files_to_scan
            FROM repositories 
            WHERE repo_hash = ? AND scan_status = 'completed'
            ORDER BY last_scanned DESC LIMIT 1
        ''', (repo_hash,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'repo_url': row[1],
                'last_scanned': row[2],
                'scan_status': 'cached',
                'total_files': row[4],
                'total_algorithms': row[5],
                'pqc_safe_count': row[6],
                'pqc_vulnerable_count': row[7],
                'current_status': 'Using cached results',
                'total_files_to_scan': row[9],
                'cached': True
            }
        return None
    
    def create_scan_record(self, repo_url: str, repo_hash: str) -> int:
        """Create initial scan record with 'pending' status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO repositories 
                (repo_url, repo_hash, scan_status, current_status, created_at)
                VALUES (?, ?, 'pending', 'Queued for scanning', CURRENT_TIMESTAMP)
            ''', (repo_url, repo_hash))
            
            repo_id = cursor.lastrowid
            conn.commit()
            return repo_id
        except sqlite3.IntegrityError:
            # Repo already exists, update it
            cursor.execute('''
                UPDATE repositories 
                SET repo_hash = ?, 
                    scan_status = 'pending',
                    current_status = 'Queued for scanning',
                    created_at = CURRENT_TIMESTAMP
                WHERE repo_url = ?
            ''', (repo_hash, repo_url))
            conn.commit()
            cursor.execute('SELECT id FROM repositories WHERE repo_url = ?', (repo_url,))
            return cursor.fetchone()[0]
        finally:
            conn.close()

    def get_pending_scans(self) -> List[Dict]:
        """Get all pending scans ordered by creation time"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, repo_url, repo_hash, created_at
            FROM repositories 
            WHERE scan_status = 'pending'
            ORDER BY created_at ASC
        ''')
        
        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'repo_url': row[1],
                'repo_hash': row[2],
                'created_at': row[3]
            })
        
        conn.close()
        return scans

    def mark_scan_processing(self, repo_id: int):
        """Mark scan as currently processing"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE repositories 
            SET scan_status = 'in_progress',
                current_status = 'Cloning repository...',
                last_scanned = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (repo_id,))
        
        conn.commit()
        conn.close()

    def update_scan_progress(self, repo_id: int, current_scanned: int, total_files_to_scan: int, status_message: str):
        """Update the scan's live progress status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE repositories 
            SET current_status = ?, total_files = ?, total_files_to_scan = ?
            WHERE id = ?
        ''', (status_message, current_scanned, total_files_to_scan, repo_id))
            
        conn.commit()
        conn.close()
    
    def save_scan_results(self, repo_id: int, scan_data: Dict):
        """Update scan record with complete results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE repositories 
                SET scan_status = 'completed',
                    total_files = ?,
                    total_algorithms = ?,
                    pqc_safe_count = ?,
                    pqc_vulnerable_count = ?,
                    last_scanned = CURRENT_TIMESTAMP,
                    current_status = 'Scan completed successfully'
                WHERE id = ?
            ''', (
                scan_data['total_files'],
                scan_data['total_algorithms'],
                scan_data['pqc_safe_count'],
                scan_data['pqc_vulnerable_count'],
                repo_id
            ))
            
            # Delete old scan results if they exist
            cursor.execute('DELETE FROM scan_results WHERE repo_id = ?', (repo_id,))
            
            for algo, data in scan_data['algorithms'].items():
                cursor.execute('''
                    INSERT INTO scan_results 
                    (repo_id, algorithm, category, is_pqc_safe, occurrences, files_affected)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    repo_id,
                    algo,
                    data['category'],
                    data['pqc_safe'],
                    data['occurrences'],
                    len(data['files'])
                ))
                
                scan_result_id = cursor.lastrowid
                
                for finding in data['findings'][:100]:
                    cursor.execute('''
                        INSERT INTO findings 
                        (scan_result_id, file_path, line_number, context, match_text)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        scan_result_id,
                        finding['file'],
                        finding['line'],
                        finding['context'][:200],
                        finding['match']
                    ))
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def mark_scan_failed(self, repo_id: int, error_message: str = None):
        """Mark a scan as failed"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        status_message = f"Failed: {error_message}" if error_message else "Scan failed unexpectedly"
        cursor.execute('''
            UPDATE repositories 
            SET scan_status = 'failed',
                current_status = ?
            WHERE id = ?
        ''', (status_message, repo_id))
        
        conn.commit()
        conn.close()
    
    def get_scan_details(self, repo_id: int) -> Dict:
        """Retrieve complete scan details"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, repo_url, repo_hash, last_scanned, scan_status,
                   total_files, total_algorithms, pqc_safe_count, pqc_vulnerable_count,
                   current_status, total_files_to_scan
            FROM repositories 
            WHERE id = ?
        ''', (repo_id,))
        repo = cursor.fetchone()
        
        if not repo:
            raise ValueError(f"Scan ID {repo_id} not found.")

        cursor.execute('''
            SELECT algorithm, category, is_pqc_safe, occurrences, files_affected
            FROM scan_results WHERE repo_id = ?
        ''', (repo_id,))
        
        algorithms = {}
        for row in cursor.fetchall():
            algo_name = row[0]
            algorithms[algo_name] = {
                'category': row[1],
                'pqc_safe': bool(row[2]),
                'occurrences': row[3],
                'files_affected': row[4]
            }
        
        conn.close()
        
        return {
            'repo_id': repo[0],
            'repo_url': repo[1],
            'repo_hash': repo[2],
            'last_scanned': repo[3],
            'scan_status': repo[4],
            'total_files': repo[5],
            'total_algorithms': repo[6],
            'pqc_safe_count': repo[7],
            'pqc_vulnerable_count': repo[8],
            'current_status': repo[9],
            'total_files_to_scan': repo[10],
            'algorithms': algorithms
        }
    
    def get_all_scans(self) -> List[Dict]:
        """Get list of all scans"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, repo_url, repo_hash, last_scanned, scan_status,
                   total_files, pqc_safe_count, pqc_vulnerable_count,
                   current_status, total_files_to_scan
            FROM repositories 
            ORDER BY last_scanned DESC
        ''')
        
        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'repo_url': row[1],
                'repo_hash': row[2],
                'last_scanned': row[3],
                'scan_status': row[4],
                'total_files': row[5],
                'pqc_safe_count': row[6],
                'pqc_vulnerable_count': row[7],
                'current_status': row[8],
                'total_files_to_scan': row[9]
            })
        
        conn.close()
        return scans


class CryptoScanner:
    """Enhanced crypto scanner with hash calculation and file listing"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.findings: Dict[str, List[Dict]] = defaultdict(list)
        self.compiled_patterns = self._compile_patterns()
        self.file_count = 0
    
    def _compile_patterns(self) -> Dict[str, List[Tuple[re.Pattern, str]]]:
        """Compile all regex patterns for efficiency"""
        compiled = {}
        for algo, info in CRYPTO_PATTERNS.items():
            compiled[algo] = [
                (re.compile(pattern, re.IGNORECASE), pattern) 
                for pattern in info['patterns']
            ]
        return compiled
    
    def get_repo_hash(self) -> str:
        """Get repository commit hash"""
        try:
            result = subprocess.run(
                ['git', '-C', str(self.repo_path), 'rev-parse', 'HEAD'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return self._hash_directory()
    
    def _hash_directory(self) -> str:
        """Calculate hash of directory contents"""
        hasher = hashlib.sha256()
        
        for file_path in sorted(self.repo_path.rglob('*')):
            if file_path.is_file() and '.git' not in file_path.parts:
                hasher.update(str(file_path.relative_to(self.repo_path)).encode())
                try:
                    with open(file_path, 'rb') as f:
                        hasher.update(f.read())
                except Exception:
                    pass
        
        return hasher.hexdigest()
    
    def get_all_code_files(self) -> List[Path]:
        """Collects all code files to scan"""
        code_files = []
        for file_path in self.repo_path.rglob('*'):
            if file_path.is_file() and '.git' not in file_path.parts:
                if file_path.suffix in CODE_EXTENSIONS or file_path.suffix == '':
                    code_files.append(file_path)
        return code_files

    def scan_file(self, file_path: Path) -> Dict[str, List[Dict]]:
        """Scan a single file for cryptographic algorithms"""
        results = defaultdict(list)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for algo, patterns in self.compiled_patterns.items():
                    for pattern, pattern_str in patterns:
                        for line_num, line in enumerate(lines, 1):
                            matches = pattern.finditer(line)
                            for match in matches:
                                results[algo].append({
                                    'file': str(file_path.relative_to(self.repo_path)),
                                    'line': line_num,
                                    'context': line.strip(),
                                    'match': match.group()
                                })
        except Exception:
            pass
        
        return results
    
    def get_results(self) -> Dict:
        """Get structured scan results"""
        pqc_safe = []
        pqc_unsafe = []
        algorithms_data = {}
        
        for algo in self.findings.keys():
            info = CRYPTO_PATTERNS[algo]
            occurrences = self.findings[algo]
            unique_files = set(occ['file'] for occ in occurrences)
            
            algo_data = {
                'name': algo,
                'category': info['category'],
                'pqc_safe': info['pqc_safe'],
                'occurrences': len(occurrences),
                'files': list(unique_files),
                'findings': occurrences
            }
            
            algorithms_data[algo] = algo_data
            
            if info['pqc_safe']:
                pqc_safe.append(algo)
            else:
                pqc_unsafe.append(algo)
        
        return {
            'total_files': self.file_count,
            'total_algorithms': len(self.findings),
            'pqc_safe_count': len(pqc_safe),
            'pqc_vulnerable_count': len(pqc_unsafe),
            'algorithms': algorithms_data
        }


def process_scan_job(repo_id: int, repo_url: str):
    """Process a single scan job"""
    temp_dir = None
    
    try:
        # Mark as processing
        db.mark_scan_processing(repo_id)
        
        # Clone repository
        temp_dir = tempfile.mkdtemp()
        subprocess.run(
            ['git', 'clone', '--depth', '1', repo_url, temp_dir],
            check=True,
            capture_output=True,
            timeout=300 # 5 minute timeout for cloning
        )
        
        # Initialize scanner
        scanner = CryptoScanner(temp_dir)
        
        # Get all files
        all_files_to_scan = scanner.get_all_code_files()
        total_files = len(all_files_to_scan)
        db.update_scan_progress(repo_id, 0, total_files, 'Preparing to scan files...')

        # Perform scan
        scanned_count = 0
        for file_path in all_files_to_scan:
            file_results = scanner.scan_file(file_path)
            for algo, occurrences in file_results.items():
                scanner.findings[algo].extend(occurrences)
            
            scanned_count += 1
            # Update progress every 10 files to reduce DB writes
            if scanned_count % 10 == 0 or scanned_count == total_files:
                db.update_scan_progress(
                    repo_id, 
                    scanned_count, 
                    total_files, 
                    f'Scanning files... ({scanned_count}/{total_files})'
                )
            scanner.file_count = scanned_count
            
        # Save results
        results = scanner.get_results()
        results['total_files'] = scanned_count
        db.save_scan_results(repo_id, results)
        
        print(f"✓ Scan completed for repo ID {repo_id}: {repo_url}")
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to clone repository: {e.stderr.decode() if e.stderr else str(e)}"
        print(f"✗ Scan failed for ID {repo_id}: {error_msg}", file=sys.stderr)
        db.mark_scan_failed(repo_id, error_msg)
    except subprocess.TimeoutExpired:
        error_msg = "Repository clone timed out (exceeded 5 minutes)"
        print(f"✗ Scan failed for ID {repo_id}: {error_msg}", file=sys.stderr)
        db.mark_scan_failed(repo_id, error_msg)
    except Exception as e:
        print(f"✗ Scan failed for ID {repo_id}: {e}", file=sys.stderr)
        db.mark_scan_failed(repo_id, str(e))
    finally:
        # Enhanced cleanup with retry logic
        if temp_dir:
            MAX_RETRIES = 5
            DELAY_SECONDS = 0.5
            for attempt in range(MAX_RETRIES):
                try:
                    shutil.rmtree(temp_dir)
                    break
                except PermissionError:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(DELAY_SECONDS)
                        DELAY_SECONDS *= 2
                    else:
                        print(f"⚠ Failed to clean up temp dir {temp_dir} after {MAX_RETRIES} attempts", file=sys.stderr)
                except Exception as e:
                    print(f"⚠ Failed to clean up temp dir {temp_dir}: {e}", file=sys.stderr)
                    break


def job_queue_worker():
    """Background worker that processes pending scans every 5 seconds"""
    print("🔄 Job queue worker started")
    
    while True:
        try:
            # Get pending scans
            pending_scans = db.get_pending_scans()
            
            if pending_scans:
                # Process the first pending scan
                scan = pending_scans[0]
                print(f"📋 Processing scan job: {scan['repo_url']} (ID: {scan['id']})")
                process_scan_job(scan['id'], scan['repo_url'])
            
            # Wait 5 seconds before checking again
            time.sleep(5)
            
        except Exception as e:
            print(f"❌ Error in job queue worker: {e}", file=sys.stderr)
            time.sleep(5)


# Flask API
app = Flask(__name__, static_folder='static')
CORS(app)
db = Database()

# Start job queue worker in background thread
worker_thread = threading.Thread(target=job_queue_worker, daemon=True)
worker_thread.start()


@app.route('/')
def index():
    """Serve frontend"""
    return send_from_directory('static', 'index.html')


@app.route('/api/scan', methods=['POST'])
def scan_repository_endpoint():
    """Queue a scan request (checks cache first)"""
    data = request.json
    repo_url = data.get('repo_url')
    
    if not repo_url:
        return jsonify({'error': 'repo_url is required'}), 400
    
    temp_dir = None
    
    try:
        # Quick clone to get hash for cache checking
        temp_dir = tempfile.mkdtemp()
        subprocess.run(
            ['git', 'clone', '--depth', '1', repo_url, temp_dir],
            check=True,
            capture_output=True,
            timeout=60
        )
        
        temp_scanner = CryptoScanner(temp_dir)
        repo_hash = temp_scanner.get_repo_hash()
        
        # Check cache
        cached = db.get_cached_scan(repo_hash)
        if cached:
            shutil.rmtree(temp_dir, ignore_errors=True)
            details = db.get_scan_details(cached['id'])
            details['cached'] = True
            details['message'] = 'Using cached scan results'
            return jsonify(details), 200
        
        # Not cached - create pending job
        repo_id = db.create_scan_record(repo_url, repo_hash)
        
        # Clean up temp clone
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        return jsonify({
            'repo_id': repo_id,
            'repo_url': repo_url,
            'repo_hash': repo_hash,
            'scan_status': 'pending',
            'current_status': 'Queued for scanning',
            'message': 'Scan request queued successfully. Worker will process it shortly.',
            'created_at': datetime.now().isoformat()
        }), 202
        
    except subprocess.CalledProcessError as e:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        error_msg = e.stderr.decode() if e.stderr else 'Failed to clone repository'
        return jsonify({'error': f'Failed to clone repository. Please check the URL. Details: {error_msg}'}), 400
    except subprocess.TimeoutExpired:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({'error': 'Repository clone timed out. The repository might be too large or the connection is slow.'}), 408
    except Exception as e:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Get list of all scans"""
    scans = db.get_all_scans()
    return jsonify(scans)


@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def get_scan_details_endpoint(scan_id):
    """Get detailed scan results"""
    try:
        details = db.get_scan_details(scan_id)
        return jsonify(details)
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@app.route('/api/queue/status', methods=['GET'])
def get_queue_status():
    """Get current queue status"""
    try:
        pending = db.get_pending_scans()
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM repositories WHERE scan_status = 'in_progress'")
        in_progress_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM repositories WHERE scan_status = 'completed'")
        completed_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM repositories WHERE scan_status = 'failed'")
        failed_count = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'pending_count': len(pending),
            'in_progress_count': in_progress_count,
            'completed_count': completed_count,
            'failed_count': failed_count,
            'pending_jobs': pending[:5] # Return first 5 pending jobs
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False, threaded=True)
