#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  BMC VULNERABILITY SCANNER v3.0 - CYBERPUNK EDITION             ║
║  Targets: iDRAC | MegaRAC | Supermicro | ASUS RAC               ║
║  CVEs: 2018-1207 | 2024-54085 | 2024-36435 | 2023-36255        ║
║  Port: 5000 | Cloudflare Ready | Zero API Keys                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import requests
import re
import json
import csv
import io
import os
import time
import random
import threading
import socket
import hashlib
import ipaddress
from urllib.parse import quote_plus
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings()

# Setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DB_DIR, 'bmc_scanner.db')

os.makedirs(DB_DIR, exist_ok=True)
os.chmod(DB_DIR, 0o777)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bmc-scanner-cyberpunk-v3'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ═══════════════════════════════════════════════════════════════════
# DATABASE MODELS
# ═══════════════════════════════════════════════════════════════════

class FoundIP(db.Model):
    """All discovered IPs from any source"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False, index=True)
    port = db.Column(db.Integer, default=443)
    source_type = db.Column(db.String(50))  # 'subnet', 'google', 'shodan', 'fofa', 'github'
    bmc_type = db.Column(db.String(50))  # 'idrac', 'megarac', 'supermicro', 'asus'
    status = db.Column(db.String(50), default='found')  # found, scanning, vulnerable, failed
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    http_title = db.Column(db.String(500))
    open_ports = db.Column(db.String(200))
    country = db.Column(db.String(100))

class VulnerableIP(db.Model):
    """Confirmed vulnerable IPs"""
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False, unique=True)
    port = db.Column(db.Integer, default=443)
    cve_id = db.Column(db.String(50))
    bmc_type = db.Column(db.String(50))
    vulnerability = db.Column(db.String(500))
    proof = db.Column(db.Text)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan_data = db.Column(db.Text)

class ScanJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_name = db.Column(db.String(200))
    scan_type = db.Column(db.String(50))  # 'subnet', 'web', 'combined'
    target_cve = db.Column(db.String(50))
    total_targets = db.Column(db.Integer, default=0)
    scanned_count = db.Column(db.Integer, default=0)
    found_count = db.Column(db.Integer, default=0)
    vuln_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), default='running')
    current_target = db.Column(db.String(100))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

# ═══════════════════════════════════════════════════════════════════
# CVE DATABASE
# ═══════════════════════════════════════════════════════════════════

CVE_DATA = {
    'idrac': {
        'cve_id': 'CVE-2018-1207',
        'name': 'Dell iDRAC',
        'description': 'Authentication Bypass in iDRAC 6/7/8',
        'ports': [443, 5900, 623, 16992, 16993],
        'dorks': [
            'intitle:"iDRAC" intitle:"Login"',
            'intitle:"iDRAC6" "Version"',
            'intitle:"iDRAC7" "Version"',
            'intitle:"iDRAC8" "Version"',
            'inurl:/restgui/start.html',
            'intitle:"Integrated Dell Remote Access Controller"',
            'intitle:"iDRAC" "User Name" "Password"',
            'intitle:"iDRAC" "Virtual Console"',
        ],
        'identifiers': ['iDRAC', 'Dell Remote Access', '/restgui/', 'idrac']
    },
    'megarac': {
        'cve_id': 'CVE-2024-54085',
        'name': 'American Megatrends MegaRAC',
        'description': 'Remote Code Execution in MegaRAC SP-X',
        'ports': [443, 623, 5900, 16992, 16993, 49152],
        'dorks': [
            'intitle:"MegaRAC" "Login"',
            'intitle:"MegaRAC SP-X"',
            'intitle:"AMI MegaRAC"',
            'inurl:"/cgi/tech1.cgi"',
            'intitle:"MegaRAC" "Copyright American Megatrends"',
            'intitle:"SP-X" "MegaRAC"',
        ],
        'identifiers': ['MegaRAC', 'American Megatrends', 'SP-X', 'AMI']
    },
    'supermicro': {
        'cve_id': 'CVE-2024-36435',
        'name': 'Supermicro IPMI/BMC',
        'description': 'IPMI vulnerability in Supermicro BMC',
        'ports': [443, 623, 5900, 16992, 16993, 49152, 49153],
        'dorks': [
            'intitle:"Supermicro" "IPMI"',
            'intitle:"Supermicro BMC"',
            'intitle:"IPMI" "Supermicro"',
            'inurl:"/cgi/url_redirect.cgi"',
            'intitle:"Supermicro" "Login"',
            'intitle:"Supermicro IPMI" "Copyright"',
        ],
        'identifiers': ['Supermicro', 'IPMI', 'Supermicro BMC']
    },
    'asus': {
        'cve_id': 'CVE-2023-36255',
        'name': 'ASUS RAC',
        'description': 'ASUS Remote Access Controller Vulnerability',
        'ports': [443, 623, 16992, 16993, 49152],
        'dorks': [
            'intitle:"ASUS" "RAC"',
            'intitle:"ASUS Remote Access"',
            'intitle:"ASUS BMC"',
            'inurl:"/ASUS_BMC/"',
            'intitle:"ASUS" "IPMI"',
        ],
        'identifiers': ['ASUS RAC', 'ASUS BMC', 'ASUS Remote']
    }
}

# ═══════════════════════════════════════════════════════════════════
# SUBNETS & TARGETS
# ═══════════════════════════════════════════════════════════════════

DEFAULT_SUBNETS = [
    '173.249.61.0/24',
    '58.220.48.0/24',
    '108.60.201.0/24',
    '98.93.210.0/24',
    '95.191.128.0/24',
    '195.231.20.0/24',
    '112.121.150.0/24',
    '219.132.90.0/24',
    '146.71.62.0/24',
    '146.88.131.0/24',
    '50.114.201.0/24',
    '178.17.164.0/24',
    '81.62.130.0/24',
    '143.109.39.0/24',
    '185.104.180.0/24',
    '213.193.255.0/24',
    '38.97.40.0/24',
    '67.23.228.0/24',
    '212.182.22.0/24',
    '135.181.234.0/24',
    '23.165.200.0/24',
    '193.29.15.0/24',
    '138.201.55.0/24',
    '51.91.106.0/24',
    '154.90.71.0/24',
    '167.17.68.0/24',
    '43.252.212.0/24',
    '108.165.97.0/24',
    '186.227.196.0/24',
    '13.208.166.0/24',
    '114.142.168.0/24',
    '185.209.39.0/24',
    '193.122.204.0/24',
    '157.238.150.0/24',
    '104.236.181.0/24',
    '38.12.134.0/24',
    '147.154.41.0/24',
    '190.85.192.0/24',
    '23.94.4.0/24',
    '189.152.113.0/24',
    '85.235.129.0/24',
    '103.13.122.0/24',
    '69.33.118.0/24',
    '146.148.223.0/24',
    '178.142.211.0/24',
    '185.53.91.0/24',
    '92.63.196.0/24',
    '137.131.26.0/24',
    '193.226.136.0/24',
    '194.34.133.0/24',
    '189.73.51.0/24',
    '51.81.166.0/24',
    '13.208.181.0/24',
    '216.238.99.0/24',
    '173.255.236.0/24',
    '78.142.59.0/24',
    '51.219.52.0/24',
    '213.173.110.0/24',
    '66.160.190.0/24',
    '151.242.124.0/24',
    '173.212.196.0/24',
    '78.41.185.0/24',
    '69.4.87.0/24',
    '85.235.135.0/24',
    '213.136.93.0/24',
    '66.93.56.0/24',
    '129.146.211.0/24',
    '216.234.219.0/24',
    '135.84.184.0/24',
    '107.167.37.0/24',
    '65.21.9.0/24',
    '207.194.107.0/24',
    '222.132.12.0/24',
    '15.235.109.0/24',
    '5.39.11.0/24',
    '72.221.36.0/24',
    '192.29.218.0/24',
    '23.184.136.0/24',
    '31.200.241.0/24',
    '158.58.173.0/24',
    '35.152.89.0/24',
    '79.127.153.0/24',
    '23.94.65.0/24',
    '200.199.72.0/24',
    '51.195.7.0/24',
    '122.8.75.0/24',
    '34.19.166.0/24',
    '23.94.150.0/24',
    '195.181.162.0/24',
    '190.144.70.0/24',
]

# ═══════════════════════════════════════════════════════════════════
# SCANNING ENGINE
# ═══════════════════════════════════════════════════════════════════

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0)',
]

def get_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }

def check_port(ip, port, timeout=3):
    """Check if port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def detect_bmc_type(ip, port=443):
    """Detect BMC type by grabbing HTTP title/banner"""
    try:
        url = f"https://{ip}:{port}"
        response = requests.get(url, headers=get_headers(), timeout=10, verify=False)
        content = response.text.lower()
        title = ''
        
        # Extract title
        if '<title>' in response.text:
            title = re.search(r'<title>(.*?)</title>', response.text, re.I)
            title = title.group(1) if title else ''
        
        # Detect type
        for bmc_type, data in CVE_DATA.items():
            for identifier in data['identifiers']:
                if identifier.lower() in content or identifier.lower() in title.lower():
                    return bmc_type, title, response.status_code
        
        # Check for generic BMC indicators
        if 'ipmi' in content or 'ipmi' in title.lower():
            return 'unknown_ipmi', title, response.status_code
        if 'bmc' in content:
            return 'unknown_bmc', title, response.status_code
            
        return None, title, response.status_code
        
    except requests.exceptions.SSLError:
        # Try HTTP
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, headers=get_headers(), timeout=10)
            return detect_bmc_type_from_content(response.text, response.status_code)
        except:
            return None, None, None
    except:
        return None, None, None

def detect_bmc_type_from_content(content, status_code):
    """Helper to detect BMC from content"""
    content = content.lower()
    for bmc_type, data in CVE_DATA.items():
        for identifier in data['identifiers']:
            if identifier.lower() in content:
                return bmc_type, '', status_code
    return None, '', status_code

def scan_subnet(subnet, job_id=None):
    """Scan a subnet for BMC targets"""
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    
    if job_id:
        job = ScanJob.query.get(job_id)
        if job:
            job.total_targets = len(hosts)
            db.session.commit()
    
    found = []
    for i, host in enumerate(hosts):
        ip = str(host)
        
        # Update progress
        if job_id and i % 10 == 0:
            job = ScanJob.query.get(job_id)
            if job:
                job.scanned_count = i
                job.current_target = ip
                db.session.commit()
        
        # Check common BMC ports
        open_ports = []
        ports_to_check = [443, 623, 5900, 16992, 16993, 49152]
        
        for port in ports_to_check:
            if check_port(ip, port):
                open_ports.append(port)
        
        if open_ports:
            # Try to detect BMC type
            bmc_type, title, status = detect_bmc_type(ip, 443 if 443 in open_ports else open_ports[0])
            
            if bmc_type:
                # Save to database
                existing = FoundIP.query.filter_by(ip_address=ip).first()
                if not existing:
                    new_ip = FoundIP(
                        ip_address=ip,
                        port=open_ports[0] if open_ports else 443,
                        source_type='subnet',
                        bmc_type=bmc_type,
                        status='found',
                        http_title=title[:200] if title else None,
                        open_ports=','.join(map(str, open_ports))
                    )
                    db.session.add(new_ip)
                    db.session.commit()
                    found.append(new_ip)
                    
                    # Update job count
                    if job_id:
                        job = ScanJob.query.get(job_id)
                        if job:
                            job.found_count += 1
                            db.session.commit()
        
        time.sleep(0.1)  # Rate limiting
    
    return found

def web_scrape_dorks(dorks, bmc_type, job_id=None):
    """Scrape Google for BMC targets using dorks"""
    found = []
    
    for dork in dorks:
        if job_id:
            job = ScanJob.query.get(job_id)
            if job:
                job.current_target = f"Scraping: {dork[:50]}..."
                db.session.commit()
        
        try:
            # Google scraping
            time.sleep(random.uniform(3, 6))
            headers = get_headers()
            url = f"https://www.google.com/search?q={quote_plus(dork)}&num=10"
            resp = requests.get(url, headers=headers, timeout=30)
            
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                for g in soup.find_all(['div', 'li'], class_=['g', 'Gx5Zad', 'fP1Qef', 'b_algo']):
                    try:
                        link = g.find('a')
                        href = link['href'] if link and 'href' in link.attrs else ''
                        
                        # Extract IPs from links
                        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', href)
                        
                        for ip in ips:
                            # Validate IP
                            parts = ip.split('.')
                            if all(0 <= int(p) <= 255 for p in parts):
                                existing = FoundIP.query.filter_by(ip_address=ip).first()
                                if not existing:
                                    new_ip = FoundIP(
                                        ip_address=ip,
                                        source_type='google',
                                        bmc_type=bmc_type,
                                        status='found'
                                    )
                                    db.session.add(new_ip)
                                    db.session.commit()
                                    found.append(new_ip)
                                    
                                    if job_id:
                                        job = ScanJob.query.get(job_id)
                                        if job:
                                            job.found_count += 1
                                            db.session.commit()
                    except:
                        continue
                        
        except Exception as e:
            print(f"[ERROR] Scraping failed: {e}")
    
    return found

def check_vulnerability(ip, bmc_type):
    """Check if IP is vulnerable to specific CVE"""
    cve_info = CVE_DATA.get(bmc_type)
    if not cve_info:
        return False, None
    
    # Basic vulnerability detection based on version indicators
    try:
        # Try HTTPS
        response = requests.get(f"https://{ip}", headers=get_headers(), timeout=10, verify=False)
        content = response.text.lower()
        
        vulnerabilities = []
        
        # iDRAC CVE-2018-1207 detection
        if bmc_type == 'idrac':
            # Look for vulnerable version indicators
            if 'idrac6' in content and ('1.85' in content or '1.82' in content or '1.80' in content):
                vulnerabilities.append('Potential CVE-2018-1207 - iDRAC6 vulnerable version')
            elif 'idrac7' in content and ('2.21' in content or '2.20' in content):
                vulnerabilities.append('Potential CVE-2018-1207 - iDRAC7 vulnerable version')
            elif 'idrac8' in content and ('2.21' in content or '2.20' in content):
                vulnerabilities.append('Potential CVE-2018-1207 - iDRAC8 vulnerable version')
        
        # MegaRAC CVE-2024-54085 detection
        elif bmc_type == 'megarac':
            if 'sp-x' in content or 'spx' in content:
                vulnerabilities.append('Potential CVE-2024-54085 - MegaRAC SP-X detected')
        
        # Supermicro CVE-2024-36435 detection
        elif bmc_type == 'supermicro':
            if 'x9' in content or 'x10' in content or 'h8' in content:
                vulnerabilities.append('Potential CVE-2024-36435 - Supermicro older generation')
        
        # ASUS CVE-2023-36255 detection
        elif bmc_type == 'asus':
            if 'asmb' in content or 'asus bmc' in content:
                vulnerabilities.append('Potential CVE-2023-36255 - ASUS BMC detected')
        
        if vulnerabilities:
            # Save to vulnerable IPs
            existing = VulnerableIP.query.filter_by(ip_address=ip).first()
            if not existing:
                vuln_ip = VulnerableIP(
                    ip_address=ip,
                    cve_id=cve_info['cve_id'],
                    bmc_type=bmc_type,
                    vulnerability='; '.join(vulnerabilities),
                    proof=content[:1000]
                )
                db.session.add(vuln_ip)
                
                # Update found IP status
                found = FoundIP.query.filter_by(ip_address=ip).first()
                if found:
                    found.status = 'vulnerable'
                
                db.session.commit()
                return True, vulnerabilities
        
        return False, None
        
    except Exception as e:
        return False, str(e)

# ═══════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route('/')
def dashboard():
    stats = {
        'total_found': FoundIP.query.count(),
        'total_vulnerable': VulnerableIP.query.count(),
        'idrac_count': FoundIP.query.filter_by(bmc_type='idrac').count(),
        'megarac_count': FoundIP.query.filter_by(bmc_type='megarac').count(),
        'supermicro_count': FoundIP.query.filter_by(bmc_type='supermicro').count(),
        'asus_count': FoundIP.query.filter_by(bmc_type='asus').count(),
        'running_jobs': ScanJob.query.filter_by(status='running').count(),
        'completed_jobs': ScanJob.query.filter_by(status='completed').count()
    }
    return render_template('dashboard.html', stats=stats, cves=CVE_DATA)

@app.route('/found-ips')
def found_ips():
    """Page for all found IPs"""
    page = request.args.get('page', 1, type=int)
    bmc_filter = request.args.get('bmc_type', '')
    status_filter = request.args.get('status', '')
    
    query = FoundIP.query
    if bmc_filter:
        query = query.filter_by(bmc_type=bmc_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    results = query.order_by(FoundIP.discovered_at.desc()).paginate(
        page=page, per_page=100, error_out=False
    )
    
    return render_template('found_ips.html', results=results, cves=CVE_DATA)

@app.route('/vulnerable-ips')
def vulnerable_ips():
    """Page for vulnerable IPs"""
    page = request.args.get('page', 1, type=int)
    cve_filter = request.args.get('cve', '')
    
    query = VulnerableIP.query
    if cve_filter:
        query = query.filter_by(cve_id=cve_filter)
    
    results = query.order_by(VulnerableIP.discovered_at.desc()).paginate(
        page=page, per_page=100, error_out=False
    )
    
    return render_template('vulnerable_ips.html', results=results, cves=CVE_DATA)

@app.route('/scanner')
def scanner():
    """Main scanner control page"""
    jobs = ScanJob.query.order_by(ScanJob.started_at.desc()).limit(10).all()
    return render_template('scanner.html', jobs=jobs, subnets=DEFAULT_SUBNETS, cves=CVE_DATA)

@app.route('/api/start-scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    scan_type = data.get('scan_type', 'combined')
    target_cve = data.get('target_cve', 'all')
    custom_subnets = data.get('subnets', [])
    
    # Create job
    job = ScanJob(
        job_name=f"BMC_SCAN_{datetime.now().strftime('%H%M%S')}",
        scan_type=scan_type,
        target_cve=target_cve,
        status='running'
    )
    db.session.add(job)
    db.session.commit()
    
    def run_scan():
        total_found = 0
        
        # Subnet scanning
        if scan_type in ['subnet', 'combined']:
            subnets = custom_subnets if custom_subnets else DEFAULT_SUBNETS[:10]  # Limit for demo
            
            for subnet in subnets:
                job.current_target = f"Scanning subnet: {subnet}"
                db.session.commit()
                
                found = scan_subnet(subnet, job.id)
                total_found += len(found)
                
                # Check vulnerabilities for found IPs
                for ip_obj in found:
                    if ip_obj.bmc_type:
                        is_vuln, details = check_vulnerability(ip_obj.ip_address, ip_obj.bmc_type)
                        if is_vuln:
                            job.vuln_count += 1
                            db.session.commit()
        
        # Web scraping
        if scan_type in ['web', 'combined']:
            for bmc_type, data in CVE_DATA.items():
                if target_cve != 'all' and data['cve_id'] != target_cve:
                    continue
                
                job.current_target = f"Scraping {bmc_type}..."
                db.session.commit()
                
                found = web_scrape_dorks(data['dorks'], bmc_type, job.id)
                total_found += len(found)
        
        job.status = 'completed'
        job.completed_at = datetime.utcnow()
        db.session.commit()
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'job_id': job.id})

@app.route('/api/job-status/<int:job_id>')
def job_status(job_id):
    """Get job status"""
    job = ScanJob.query.get_or_404(job_id)
    progress = (job.scanned_count / max(job.total_targets, 1)) * 100 if job.total_targets > 0 else 0
    
    return jsonify({
        'id': job.id,
        'name': job.job_name,
        'status': job.status,
        'total': job.total_targets,
        'scanned': job.scanned_count,
        'found': job.found_count,
        'vulnerable': job.vuln_count,
        'progress': round(min(progress, 100), 1),
        'current': job.current_target,
        'started': job.started_at.strftime('%H:%M:%S') if job.started_at else ''
    })

@app.route('/api/active-jobs')
def active_jobs():
    """Get all active jobs"""
    jobs = ScanJob.query.filter_by(status='running').all()
    return jsonify([{
        'id': j.id,
        'name': j.job_name,
        'progress': round((j.scanned_count / max(j.total_targets, 1)) * 100, 1) if j.total_targets else 0,
        'found': j.found_count,
        'vulnerable': j.vuln_count,
        'current': j.current_target
    } for j in jobs])

@app.route('/api/recent-found')
def recent_found():
    """Get recently found IPs"""
    results = FoundIP.query.order_by(FoundIP.discovered_at.desc()).limit(50).all()
    return jsonify([{
        'id': r.id,
        'ip': r.ip_address,
        'port': r.port,
        'type': r.bmc_type,
        'status': r.status,
        'source': r.source_type,
        'time': r.discovered_at.strftime('%H:%M:%S')
    } for r in results])

@app.route('/api/recent-vulnerable')
def recent_vulnerable():
    """Get recently found vulnerable IPs"""
    results = VulnerableIP.query.order_by(VulnerableIP.discovered_at.desc()).limit(50).all()
    return jsonify([{
        'id': r.id,
        'ip': r.ip_address,
        'cve': r.cve_id,
        'type': r.bmc_type,
        'vuln': r.vulnerability,
        'time': r.discovered_at.strftime('%H:%M:%S')
    } for r in results])

@app.route('/api/export/<type>/<format>')
def export_data(type, format):
    """Export data"""
    if type == 'found':
        results = FoundIP.query.all()
        if format == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['IP', 'Port', 'Type', 'Status', 'Source', 'Open Ports', 'Discovered'])
            for r in results:
                writer.writerow([r.ip_address, r.port, r.bmc_type, r.status, r.source_type, r.open_ports, r.discovered_at])
            output.seek(0)
            return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name=f'bmc_found_{datetime.now().strftime("%Y%m%d")}.csv')
    
    elif type == 'vulnerable':
        results = VulnerableIP.query.all()
        if format == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['IP', 'Port', 'CVE', 'Type', 'Vulnerability', 'Discovered'])
            for r in results:
                writer.writerow([r.ip_address, r.port, r.cve_id, r.bmc_type, r.vulnerability, r.discovered_at])
            output.seek(0)
            return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name=f'bmc_vulnerable_{datetime.now().strftime("%Y%m%d")}.csv')
    
    return jsonify({'error': 'Invalid export'}), 400

@app.route('/api/delete-found/<int:id>', methods=['DELETE'])
def delete_found(id):
    """Delete a found IP"""
    ip = FoundIP.query.get_or_404(id)
    db.session.delete(ip)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/clear-all', methods=['POST'])
def clear_all():
    """Clear all data"""
    FoundIP.query.delete()
    VulnerableIP.query.delete()
    ScanJob.query.delete()
    db.session.commit()
    return jsonify({'success': True})

@app.route('/settings')
def settings():
    """Settings page"""
    return render_template('settings.html', cves=CVE_DATA, subnets=DEFAULT_SUBNETS)

# INIT
with app.app_context():
    db.create_all()
    print(f"[✓] Database ready: {DB_PATH}")

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║  BMC VULNERABILITY SCANNER v3.0                        ║
    ║  Targets: iDRAC | MegaRAC | Supermicro | ASUS           ║
    ║  Port: 5000 | Cloudflare Ready | Zero API Keys          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
