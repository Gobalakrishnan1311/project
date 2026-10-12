import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    JSON
)
from sqlalchemy.orm import relationship
from .database import Base

def generate_uuid():
    return str(uuid.uuid4())

class Project(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")

class Target(Base):
    __tablename__ = "targets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    hostname = Column(String(255), nullable=False, index=True)
    scheme = Column(String(10), nullable=False, default="https")
    user_authorized = Column(Boolean, default=False, nullable=False)
    owner_confirmation = Column(String(512), nullable=True)
    allow_subdomains = Column(Boolean, default=False)
    excluded_hosts = Column(JSON, default=list)
    excluded_paths = Column(JSON, default=list)
    request_timeout = Column(Integer, default=8000)
    max_requests = Column(Integer, default=50)
    status = Column(String(30), default="ready")
    last_scan_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    project = relationship("Project", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    target_hostname = Column(String(255), nullable=False)
    status = Column(String(30), default="pending", index=True)  # pending, running, completed, cancelled, failed
    progress = Column(Integer, default=0)
    checks_run = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    config = Column(JSON, default=dict)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    project = relationship("Project", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    level = Column(String(20), default="info")  # info, warn, error
    message = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="logs")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # informational, low, medium, high, critical
    category = Column(String(100), nullable=False, index=True)
    affected_url = Column(String(2048), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=False)
    impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    verification_status = Column(String(50), default="New", index=True)  # New, Needs Review, Confirmed, False Positive, Fixed, Accepted Risk
    manual_verification = Column(Text, nullable=True)
    first_discovered = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_observed = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")
    target = relationship("Target", back_populates="findings")

class ScanConfiguration(Base):
    __tablename__ = "scan_configurations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    timeout = Column(Integer, default=8000)
    max_requests = Column(Integer, default=50)
    concurrency = Column(Integer, default=2)
    delay_ms = Column(Integer, default=250)
    created_at = Column(DateTime, default=datetime.utcnow)
