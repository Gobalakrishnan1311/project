import asyncio
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field

from ..database import get_db
from ..models import Project, Target, Scan, ScanLog, Finding
from ..scope_guard import ScopeGuard, ScopeGuardError
from ..scanner.engine import ScanEngine
from ..reports import ReportGenerator

router = APIRouter()

# Pydantic Schemas
class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1)
    description: Optional[str] = None

class TargetCreate(BaseModel):
    project_id: Optional[str] = None
    url: str
    user_authorized: bool = True
    owner_confirmation: Optional[str] = None
    allow_subdomains: bool = False
    excluded_hosts: List[str] = []
    excluded_paths: List[str] = []
    request_timeout: int = 8000
    max_requests: int = 50

class ScanCreate(BaseModel):
    target_id: str
    timeout: int = 8000
    max_requests: int = 50
    concurrency: int = 2
    delay_ms: int = 250

class FindingUpdate(BaseModel):
    verification_status: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None

class ReconDnsRequest(BaseModel):
    hostname: str

class ReconHttpRequest(BaseModel):
    url: str

class InspectorRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: dict = {}
    timeout: int = 8000

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "WebBug Hunter Backend",
        "mode": "authorized_bug_bounty_testing",
        "scope_guard": "enforced"
    }

@router.get("/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    targets = db.query(Target).all()
    scans = db.query(Scan).all()
    findings = db.query(Finding).all()

    severity_counts = {
        "critical": len([f for f in findings if f.severity == "critical"]),
        "high": len([f for f in findings if f.severity == "high"]),
        "medium": len([f for f in findings if f.severity == "medium"]),
        "low": len([f for f in findings if f.severity == "low"]),
        "informational": len([f for f in findings if f.severity == "informational"]),
    }

    recent_scans = db.query(Scan).order_by(Scan.started_at.desc()).limit(5).all()
    latest_findings = db.query(Finding).order_by(Finding.first_discovered.desc()).limit(6).all()

    return {
        "metrics": {
            "totalTargets": len(targets),
            "totalScans": len(scans),
            "completedScans": len([s for s in scans if s.status == "completed"]),
            "totalFindings": len(findings),
            "severityCounts": severity_counts
        },
        "recentScans": recent_scans,
        "latestFindings": latest_findings
    }

# Projects
@router.get("/projects")
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).all()

@router.post("/projects", status_code=201)
def create_project(data: ProjectCreate, db: Session = Depends(get_db)):
    proj = Project(name=data.name, description=data.description)
    db.add(proj)
    db.commit()
    db.refresh(proj)
    return proj

# Targets
@router.get("/targets")
def list_targets(db: Session = Depends(get_db)):
    return db.query(Target).all()

@router.post("/targets", status_code=201)
def create_target(data: TargetCreate, db: Session = Depends(get_db)):
    if not data.user_authorized:
        raise HTTPException(status_code=403, detail="ScopeGuard requires explicit owner authorization confirmation.")

    try:
        norm_url, hostname, scheme = ScopeGuard.normalize_target(data.url)
    except ScopeGuardError as e:
        raise HTTPException(status_code=400, detail=str(e))

    proj_id = data.project_id
    if not proj_id:
        proj = db.query(Project).first()
        if not proj:
            proj = Project(name="Default Pentest Scope", description="Default security testing scope.")
            db.add(proj)
            db.commit()
            db.refresh(proj)
        proj_id = proj.id

    target = Target(
        project_id=proj_id,
        url=norm_url,
        hostname=hostname,
        scheme=scheme,
        user_authorized=True,
        owner_confirmation=data.owner_confirmation or "Authorized by tester",
        allow_subdomains=data.allow_subdomains,
        excluded_hosts=data.excluded_hosts,
        excluded_paths=data.excluded_paths,
        request_timeout=data.request_timeout,
        max_requests=data.max_requests,
        status="ready"
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target

@router.get("/targets/{target_id}")
def get_target(target_id: str, db: Session = Depends(get_db)):
    t = db.query(Target).filter(Target.id == target_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Target not found")
    return t

@router.delete("/targets/{target_id}")
def delete_target(target_id: str, db: Session = Depends(get_db)):
    t = db.query(Target).filter(Target.id == target_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(t)
    db.commit()
    return {"success": True, "message": "Target deleted"}

# Scans
@router.get("/scans")
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.started_at.desc()).all()

async def execute_scan_background(scan_id: str):
    from ..database import SessionLocal
    db = SessionLocal()
    try:
        engine = ScanEngine(db, scan_id)
        await engine.run()
    finally:
        db.close()

@router.post("/scans", status_code=201)
def start_scan(data: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == data.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = Scan(
        target_id=target.id,
        project_id=target.project_id,
        target_url=target.url,
        target_hostname=target.hostname,
        status="pending",
        progress=0,
        config={
            "timeout": data.timeout,
            "max_requests": data.max_requests,
            "concurrency": data.concurrency,
            "delay_ms": data.delay_ms
        }
    )
    db.add(scan)
    target.status = "scanning"
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(execute_scan_background, scan.id)
    return scan

@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    logs = db.query(ScanLog).filter(ScanLog.scan_id == scan_id).order_by(ScanLog.timestamp.asc()).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return {
        **s.__dict__,
        "logs": logs,
        "findings": findings
    }

@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    s.status = "cancelled"
    db.commit()
    return {"success": True, "message": "Scan cancelled"}

# Findings
@router.get("/findings")
def list_findings(
    target_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    q = db.query(Finding)
    if target_id:
        q = q.filter(Finding.target_id == target_id)
    if severity and severity != "all":
        q = q.filter(Finding.severity == severity)
    if status and status != "all":
        q = q.filter(Finding.verification_status == status)
    return q.order_by(Finding.first_discovered.desc()).all()

@router.patch("/findings/{finding_id}")
def update_finding(finding_id: str, data: FindingUpdate, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    if data.verification_status:
        f.verification_status = data.verification_status
    if data.severity:
        f.severity = data.severity
    if data.notes:
        f.manual_verification = f"{f.manual_verification or ''}\nNote: {data.notes}"
    db.commit()
    db.refresh(f)
    return f

@router.delete("/findings/{finding_id}")
def delete_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(f)
    db.commit()
    return {"success": True, "message": "Finding deleted"}

# Reports
@router.get("/reports/{scan_id}/json")
def get_json_report(scan_id: str, db: Session = Depends(get_db)):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    proj = db.query(Project).filter(Project.id == s.project_id).first()
    t = db.query(Target).filter(Target.id == s.target_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    json_data = ReportGenerator.generate_json(s, proj, t, findings)
    return Response(content=json_data, media_type="application/json", headers={
        "Content-Disposition": f"attachment; filename=report_{scan_id}.json"
    })

@router.get("/reports/{scan_id}/csv")
def get_csv_report(scan_id: str, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    csv_data = ReportGenerator.generate_csv(findings)
    return Response(content=csv_data, media_type="text/csv", headers={
        "Content-Disposition": f"attachment; filename=findings_{scan_id}.csv"
    })

@router.get("/reports/{scan_id}/html")
def get_html_report(scan_id: str, db: Session = Depends(get_db)):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    proj = db.query(Project).filter(Project.id == s.project_id).first()
    t = db.query(Target).filter(Target.id == s.target_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    html_data = ReportGenerator.generate_html(s, proj, t, findings)
    return Response(content=html_data, media_type="text/html")
