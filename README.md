# WebBug Hunter — Basic Website Bug Bounty Testing Tool

**WebBug Hunter** is an authorized website security testing, reconnaissance, and vulnerability auditing tool designed for authorized bug bounty researchers, penetration testers, and security engineers.

The application combines a high-density cybersecurity dark-theme dashboard with a strict **ScopeGuard** perimeter to ensure all testing is strictly confined to authorized targets while blocking SSRF (Server-Side Request Forgery), loopback manipulation, and prohibited network ranges.

---

## Architecture Overview

```
webbug-hunter/
├── frontend/ (and root Vite/React app)
│   ├── src/
│   │   ├── components/      # Sidebar, TopBar, modals, navigation
│   │   ├── pages/           # Dashboard, Targets, Recon, Scanner, Inspector, Findings, Reports, Settings
│   │   ├── services/        # Axios API client (/api/* endpoints)
│   │   ├── types.ts         # TypeScript schema definitions
│   │   ├── App.tsx          # Root tab router & state engine
│   │   └── main.tsx         # React root
│   └── package.json
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI application & lifespan
│   │   ├── api/endpoints.py # REST endpoints (targets, scans, findings, recon, reports)
│   │   ├── scanner/
│   │   │   ├── checks.py    # 10 modular defensive security checks
│   │   │   └── engine.py    # Asynchronous scanner engine
│   │   ├── scope_guard.py   # Dedicated SSRF & ScopeGuard protection module
│   │   ├── models.py        # SQLAlchemy ORM models (Project, Target, Scan, Finding, ScanLog)
│   │   ├── database.py      # SQLite connection & session maker
│   │   └── reports.py       # HTML, JSON, and CSV report generators
│   ├── tests/
│   │   ├── test_scope_guard.py # ScopeGuard unit tests
│   │   └── test_scanner.py     # Scanner checks unit tests
│   └── requirements.txt
├── server/                  # Fullstack Node/Express dev-server API proxy & runner
├── Dockerfile               # Multi-stage production container build
├── docker-compose.yml       # Docker Compose service definition
└── README.md                # Documentation & installation guide
```

---

## Key Modules & Capabilities

1. **Dashboard Overview**:
   - Total targets, total scans, completed scans, total findings.
   - Severity distribution (Critical, High, Medium, Low, Informational).
   - Recent scan execution activity and latest discovered findings.
2. **Target Scope Management**:
   - Target hostname and URL normalization.
   - Mandatory Owner Authorization certification.
   - Subdomain boundaries (`*.domain.com`).
   - Host and path exclusions list.
   - Rate limiting, concurrency, and request timeouts.
3. **Reconnaissance Engine**:
   - Live DNS Lookups: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME` records.
   - HTTP/HTTPS status, latency, response headers, Content-Type.
   - TLS certificate validity, issuer, and expiration inspection.
   - `robots.txt` and `sitemap.xml` passive inspection.
   - Passive technology fingerprinting (Server, X-Powered-By, CDNs, Frameworks).
4. **10 Modular Security Checks**:
   - Check 1: Missing or weak HTTP security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
   - Check 2: Missing or weak Content Security Policy (CSP).
   - Check 3: Strict-Transport-Security (HSTS) downgrade resistance.
   - Check 4: Cookie security flags (`Secure`, `HttpOnly`, `SameSite`).
   - Check 5: TLS certificate posture, validity, and expiration warning.
   - Check 6: Insecure Cross-Origin Resource Sharing (CORS) wildcard credentials & null origin.
   - Check 7: Server version & software banner information disclosure.
   - Check 8: Public directory index listings (`Index of /`).
   - Check 9: Exposed diagnostic & sensitive files (`.env`, `.git/HEAD`, `robots.txt` disallows).
   - Check 10: Harmless reflected input marker check using non-executable benign tokens.
5. **HTTP Request / Response Inspector**:
   - Manual `GET` and `HEAD` probes with custom headers.
   - Raw response headers, response cookies, response duration, and body text preview.
   - Protected by ScopeGuard against SSRF.
6. **Vulnerability Findings Manager**:
   - Search by title, category, or endpoint.
   - Filter by severity and verification status (`New`, `Needs Review`, `Confirmed`, `False Positive`, `Fixed`, `Accepted Risk`).
   - Triage detail drawer with evidence, security impact, defensive remediation, and analyst notes.
7. **Compliance & Audit Reports**:
   - One-click downloads in **HTML**, **JSON**, and **CSV**.
   - Automatic credential redaction and sanitization.
8. **ScopeGuard Perimeter**:
   - Blocks `127.0.0.0/8`, `::1`, `0.0.0.0/8` (localhost).
   - Blocks `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 private subnets).
   - Blocks `169.254.169.254` and cloud metadata services.
   - Blocks unsupported schemes (`file://`, `gopher://`, `ftp://`).
   - Re-resolves DNS before requests to prevent DNS rebinding.

---

## Windows 10/11 Installation & Setup Guide

### 1. Prerequisites
Ensure you have the following installed on Windows 10/11:
- **Python 3.10+** (download from [python.org](https://www.python.org/) and make sure to check **"Add Python to PATH"** during installation).
- **Node.js 18+ or 20+ (LTS)** (download from [nodejs.org](https://nodejs.org/)).
- **Git for Windows** (download from [git-scm.com](https://git-scm.com/)).

Open **PowerShell** or **Command Prompt** as Administrator to verify:
```powershell
python --version
node --version
npm --version
```

---

### 2. Backend Setup (Python FastAPI + SQLite)

Open PowerShell and navigate to the project root:
```powershell
cd C:\path\to\webbug-hunter
```

#### Step A: Create and Activate Python Virtual Environment
```powershell
python -m venv venv
# In PowerShell:
.\venv\Scripts\Activate.ps1
# (Or in CMD):
# .\venv\Scripts\activate.bat
```
*(Note: If PowerShell shows an ExecutionPolicy error, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` once).*

#### Step B: Install Backend Dependencies
```powershell
pip install --upgrade pip
pip install -r backend/requirements.txt
```

#### Step C: Run Backend Automated Tests
```powershell
pytest backend/tests -v
```

#### Step D: Start the FastAPI Backend
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
The FastAPI backend is now running at `http://127.0.0.1:8000`.
You can visit `http://127.0.0.1:8000/docs` to view interactive Swagger UI documentation.

---

### 3. Frontend Setup (React + Vite + Tailwind CSS)

Open a **second** terminal window:
```powershell
cd C:\path\to\webbug-hunter
```

#### Step A: Install Frontend Dependencies
```powershell
npm install
```

#### Step B: Start Frontend Development Server
```powershell
npm run dev
```

Open your browser and navigate to:
```
http://localhost:3000
```

---

## Docker Quickstart (Alternative)

If Docker Desktop for Windows is installed:

```powershell
# Build and run container
docker-compose up --build -d

# Check status
docker-compose ps

# Access dashboard
http://localhost:8000
```

To stop:
```powershell
docker-compose down
```

---

## Troubleshooting Common Errors

1. **`ScopeGuard Error: Access to localhost / loopback is prohibited`**
   - ScopeGuard by design rejects `127.0.0.1`, `localhost`, and internal RFC 1918 IPs to prevent SSRF vulnerabilities. Always specify a public test domain (e.g. `example.com` or your authorized staging domain).
2. **`Script Execution Disabled in PowerShell`**
   - Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` in PowerShell to enable the virtual environment activation script.
3. **Port 8000 or 3000 Already In Use**
   - In PowerShell, run `Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process` or use another port with `--port 8001`.
4. **Missing Python Modules**
   - Ensure the virtual environment is active: your terminal prompt should show `(venv)`. Run `pip install -r backend/requirements.txt`.

---

## Defensive Ethical Testing Notice

WebBug Hunter is built strictly for **authorized** security auditing, defensive gap analysis, and bug bounty scope verification. It performs non-destructive passive checks and harmless benign markers. Unauthorized scanning against systems without explicit permission is strictly prohibited.
