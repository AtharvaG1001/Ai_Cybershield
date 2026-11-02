"""
AI CyberShield — FastAPI Backend
=================================
Replaces the original Flask app with a fully documented FastAPI backend
including Pydantic validation, SQLAlchemy persistence, and full test support.
"""

import os
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import create_tables, get_db, Scan, Finding, ModelEvaluation
from schemas import (
    URLScanRequest, EmailScanRequest,
    URLScanResponse, EmailScanResponse,
    DashboardSummary, ModelStatus, ModelMetrics,
    HealthResponse, IntegrationsResponse, IntegrationStatus,
    ScansListResponse, ScanSummary, ScanDetail, FindingResponse,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application Initialisation
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI CyberShield",
    description="Intelligent Phishing Detection & Threat Intelligence Platform",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create DB tables on startup
create_tables()

# ---------------------------------------------------------------------------
# Lazy-load heavy engines (avoid import-time failures)
# ---------------------------------------------------------------------------

_url_engine = None
_email_engine = None
_model_predictor = None


def get_url_engine():
    global _url_engine
    if _url_engine is None:
        from ai_engine import AIEngine
        _url_engine = AIEngine()
    return _url_engine


def get_email_engine():
    global _email_engine
    if _email_engine is None:
        from email_engine.email_engine import EmailEngine
        _email_engine = EmailEngine()
    return _email_engine


def get_model_predictor():
    global _model_predictor
    if _model_predictor is None:
        from model_predictor import ModelPredictor
        _model_predictor = ModelPredictor()
    return _model_predictor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_META_PATH = os.path.join(BASE_DIR, "models", "model_metadata.json")
FEATURE_NAMES_PATH = os.path.join(BASE_DIR, "models", "feature_names.json")


def _risk_category(score: float) -> str:
    if score < 25:
        return "LOW"
    elif score < 50:
        return "MEDIUM"
    elif score < 75:
        return "HIGH"
    else:
        return "CRITICAL"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _save_url_scan(db: Session, url: str, result: dict) -> str:
    """Persist a URL scan result to the database."""
    scan_id = str(uuid.uuid4())
    threat = result.get("threat_analysis") or {}
    ml = result.get("machine_learning") or {}

    risk_score = float(threat.get("overall_score", 0))
    verdict = threat.get("verdict", "INCONCLUSIVE")
    risk_cat = _risk_category(risk_score)

    scan = Scan(
        id=scan_id,
        scan_type="url",
        input_value=url[:500],
        risk_category=risk_cat,
        risk_score=risk_score,
        verdict=verdict,
        ml_prediction=ml.get("prediction"),
        ml_confidence=ml.get("confidence"),
        model_version=ml.get("model_version", "1.0.0"),
        scan_status="SUCCESS" if result.get("status") == "SUCCESS" else "PARTIAL",
    )
    db.add(scan)

    # Findings from ML
    if ml.get("prediction") == "PHISHING":
        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            finding_type="ml",
            severity="HIGH" if (ml.get("phishing_probability") or 0) >= 70 else "MEDIUM",
            title="ML Model: Phishing Detected",
            description=(
                f"Machine learning classifier predicted PHISHING with "
                f"{ml.get('phishing_probability', '?')}% probability."
            ),
            evidence=json.dumps({
                "phishing_probability": ml.get("phishing_probability"),
                "confidence": ml.get("confidence"),
            }),
            evidence_source="RandomForestClassifier",
        )
        db.add(finding)

    # Findings from warnings
    for module_key, severity_map in [
        ("ssl", {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}),
        ("dns", {"HIGH": "HIGH", "MEDIUM": "MEDIUM"}),
        ("whois", {"HIGH": "HIGH", "MEDIUM": "MEDIUM"}),
        ("keywords", {"HIGH": "MEDIUM", "MEDIUM": "LOW"}),
    ]:
        mod = result.get(module_key) or {}
        for warning in mod.get("warnings", []):
            level = mod.get("security_level", "LOW")
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                finding_type=module_key,
                severity=severity_map.get(level, "LOW"),
                title=f"{mod.get('module', module_key.upper())}: {warning[:80]}",
                description=warning,
                evidence=None,
                evidence_source=mod.get("module", module_key),
            )
            db.add(finding)

    db.commit()
    return scan_id


def _save_email_scan(db: Session, result: dict) -> str:
    """Persist an email scan result to the database."""
    scan_id = str(uuid.uuid4())
    threat = result.get("threat_analysis", {}).get("data", {})
    email_data = result.get("email", {})

    risk_score = float(threat.get("overall_score", 0))
    verdict = threat.get("verdict", "INCONCLUSIVE")
    risk_cat = _risk_category(risk_score)
    subject = email_data.get("subject", "")[:100] or "(no subject)"

    scan = Scan(
        id=scan_id,
        scan_type="email",
        input_value=subject,
        risk_category=risk_cat,
        risk_score=risk_score,
        verdict=verdict,
        ml_prediction=None,
        ml_confidence=None,
        model_version=None,
        scan_status="SUCCESS" if result.get("status") == "SUCCESS" else "PARTIAL",
    )
    db.add(scan)

    for warning in result.get("warnings", [])[:20]:
        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            finding_type="email",
            severity="MEDIUM",
            title=warning[:80],
            description=warning,
            evidence=None,
            evidence_source="Email Engine",
        )
        db.add(finding)

    db.commit()
    return scan_id


# ---------------------------------------------------------------------------
# Health & Status
# ---------------------------------------------------------------------------

@app.get("/api/health", response_model=HealthResponse, tags=["System"])
def health_check(db: Session = Depends(get_db)):
    """System health check."""
    model_ok = False
    try:
        get_model_predictor()
        model_ok = True
    except Exception:
        pass

    db_ok = False
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    return HealthResponse(
        status="ok",
        model_loaded=model_ok,
        database_ok=db_ok,
        version="2.0.0",
    )


@app.get("/api/model/status", response_model=ModelStatus, tags=["Model"])
def model_status():
    """Return the loaded model's metadata."""
    try:
        predictor = get_model_predictor()
        feature_names = predictor.feature_names or []
        return ModelStatus(
            loaded=True,
            model_type=type(predictor.model).__name__,
            n_features=predictor.n_features,
            model_version=predictor.model_version,
            feature_names=feature_names,
        )
    except Exception as e:
        return ModelStatus(
            loaded=False,
            model_type="unavailable",
            n_features=0,
            model_version="unavailable",
        )


@app.get("/api/model/metrics", response_model=ModelMetrics, tags=["Model"])
def model_metrics(db: Session = Depends(get_db)):
    """Return evaluation metrics from the most recent evaluation run."""
    eval_record = (
        db.query(ModelEvaluation)
        .order_by(ModelEvaluation.evaluated_at.desc())
        .first()
    )

    if eval_record is None:
        # Return placeholder indicating metrics not yet computed
        return ModelMetrics(
            available=False,
            model_version="1.0.0",
            dataset_id="PhiUSIIL_Phishing_URL_Dataset",
            evaluated_at=None,
        )

    cm = None
    if eval_record.confusion_matrix:
        try:
            cm = json.loads(eval_record.confusion_matrix)
        except Exception:
            pass

    return ModelMetrics(
        available=True,
        model_version=eval_record.model_version,
        dataset_id=eval_record.dataset_id,
        evaluated_at=eval_record.evaluated_at.isoformat() if eval_record.evaluated_at else None,
        accuracy=eval_record.accuracy,
        precision=eval_record.precision,
        recall=eval_record.recall,
        f1_score=eval_record.f1_score,
        roc_auc=eval_record.roc_auc,
        false_positive_rate=eval_record.false_positive_rate,
        false_negative_rate=eval_record.false_negative_rate,
        dataset_size=eval_record.dataset_size,
        phishing_count=eval_record.phishing_count,
        legitimate_count=eval_record.legitimate_count,
        confusion_matrix=cm,
    )


# ---------------------------------------------------------------------------
# Scan Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/scan/url", tags=["Scanning"])
def scan_url(request: URLScanRequest, db: Session = Depends(get_db)):
    """
    Analyze a URL for phishing indicators.

    Returns ML prediction, rule-based findings, SSL/DNS/WHOIS analysis,
    and an aggregated threat score.
    """
    url = request.url
    try:
        engine = get_url_engine()
        result = engine.analyze(url)
    except Exception as e:
        logger.error("URL engine failure: %s", e)
        raise HTTPException(status_code=500, detail=f"Analysis engine error: {str(e)}")

    if result.get("status") == "FAILED":
        raise HTTPException(
            status_code=400,
            detail=result.get("message", "URL analysis failed."),
        )

    # Persist
    scan_id = _save_url_scan(db, url, result)

    threat = result.get("threat_analysis") or {}
    ml = result.get("machine_learning") or {}
    risk_score = float(threat.get("overall_score", 0))
    risk_cat = _risk_category(risk_score)

    # Build explainable findings list
    findings = []
    for module_key in ("ssl", "dns", "whois", "keywords"):
        mod = result.get(module_key) or {}
        for warning in mod.get("warnings", []):
            findings.append({
                "source": mod.get("module", module_key),
                "severity": mod.get("security_level", "LOW"),
                "description": warning,
            })

    # Module errors as limitations
    limitations = result.get("module_errors", [])

    return {
        "scan_id": scan_id,
        "status": result.get("status", "SUCCESS"),
        "url": url,
        "normalized_url": url,
        "risk_score": risk_score,
        "risk_category": risk_cat,
        "verdict": threat.get("verdict", "INCONCLUSIVE"),
        "ml_prediction": ml.get("prediction"),
        "ml_confidence": ml.get("confidence"),
        "phishing_probability": ml.get("phishing_probability"),
        "legitimate_probability": ml.get("legitimate_probability"),
        "url_features": ml.get("features", {}),
        "rule_findings": [],
        "ssl": result.get("ssl", {}),
        "dns": result.get("dns", {}),
        "whois": result.get("whois", {}),
        "keywords": result.get("keywords", {}),
        "findings": findings,
        "warnings": threat.get("warnings", []),
        "recommendations": threat.get("recommendations", []),
        "scan_timestamp": _now_iso(),
        "model_version": ml.get("model_version", "1.0.0"),
        "limitations": limitations,
        "score_breakdown": threat.get("score_breakdown", {}),
    }


@app.post("/api/scan/email", tags=["Scanning"])
def scan_email(request: EmailScanRequest, db: Session = Depends(get_db)):
    """
    Analyze email content for phishing indicators.

    Accepts raw email text (RFC 2822 format or plain text).
    """
    try:
        engine = get_email_engine()
        result = engine.analyze(request.raw_email)
    except Exception as e:
        logger.error("Email engine failure: %s", e)
        raise HTTPException(status_code=500, detail=f"Email analysis engine error: {str(e)}")

    if result.get("status") == "FAILED":
        raise HTTPException(
            status_code=400,
            detail="Email analysis failed. " + "; ".join(result.get("warnings", [])),
        )

    scan_id = _save_email_scan(db, result)

    threat_data = result.get("threat_analysis", {}).get("data", {})
    email_data = result.get("email", {})

    risk_score = float(threat_data.get("overall_score", 0))
    risk_cat = _risk_category(risk_score)

    return {
        "scan_id": scan_id,
        "status": result.get("status", "SUCCESS"),
        "risk_score": risk_score,
        "risk_category": risk_cat,
        "verdict": threat_data.get("verdict", "INCONCLUSIVE"),
        "sender": email_data.get("sender"),
        "subject": email_data.get("subject"),
        "link_count": email_data.get("link_count", 0),
        "links": email_data.get("links", []),
        "findings": [],
        "warnings": result.get("warnings", []),
        "recommendations": result.get("recommendations", []),
        "scan_timestamp": _now_iso(),
        "keyword_analysis": result.get("keyword_analysis", {}),
        "sender_analysis": result.get("sender_analysis", {}),
        "link_analysis": result.get("link_analysis", {}),
        "spam_analysis": result.get("spam_analysis", {}),
        "intent_analysis": result.get("intent_analysis", {}),
        "threat_analysis": result.get("threat_analysis", {}),
    }


# ---------------------------------------------------------------------------
# History & Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/scans", tags=["History"])
def list_scans(
    scan_type: Optional[str] = None,
    risk_category: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """List scan history with optional filtering and pagination."""
    query = db.query(Scan)

    if scan_type:
        query = query.filter(Scan.scan_type == scan_type.lower())
    if risk_category:
        query = query.filter(Scan.risk_category == risk_category.upper())

    total = query.count()
    scans = (
        query.order_by(Scan.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "scans": [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "input_value": s.input_value,
                "risk_category": s.risk_category,
                "risk_score": s.risk_score,
                "verdict": s.verdict,
                "ml_prediction": s.ml_prediction,
                "ml_confidence": s.ml_confidence,
                "scan_status": s.scan_status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in scans
        ],
    }


@app.get("/api/scans/{scan_id}", tags=["History"])
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Get a single scan record with its findings."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    return {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "input_value": scan.input_value,
        "risk_category": scan.risk_category,
        "risk_score": scan.risk_score,
        "verdict": scan.verdict,
        "ml_prediction": scan.ml_prediction,
        "ml_confidence": scan.ml_confidence,
        "model_version": scan.model_version,
        "scan_status": scan.scan_status,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "evidence_source": f.evidence_source,
            }
            for f in findings
        ],
    }


@app.get("/api/dashboard/summary", tags=["Dashboard"])
def dashboard_summary(db: Session = Depends(get_db)):
    """Return aggregated statistics for the main dashboard."""
    total = db.query(Scan).count()
    url_count = db.query(Scan).filter(Scan.scan_type == "url").count()
    email_count = db.query(Scan).filter(Scan.scan_type == "email").count()

    high_risk = db.query(Scan).filter(Scan.risk_category == "HIGH").count()
    critical = db.query(Scan).filter(Scan.risk_category == "CRITICAL").count()
    safe = db.query(Scan).filter(Scan.risk_category == "LOW").count()

    from datetime import date
    today_start = datetime.combine(date.today(), datetime.min.time())
    scans_today = db.query(Scan).filter(Scan.created_at >= today_start).count()

    risk_dist = {}
    for cat in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        risk_dist[cat] = db.query(Scan).filter(Scan.risk_category == cat).count()

    recent = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    return {
        "total_scans": total,
        "url_scans": url_count,
        "email_scans": email_count,
        "high_risk_count": high_risk,
        "critical_count": critical,
        "safe_count": safe,
        "scans_today": scans_today,
        "risk_distribution": risk_dist,
        "recent_scans": [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "input_value": s.input_value,
                "risk_category": s.risk_category,
                "risk_score": s.risk_score,
                "verdict": s.verdict,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in recent
        ],
    }


@app.get("/api/integrations/status", tags=["System"])
def integrations_status():
    """Return status of configured external threat intelligence providers."""
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    integrations = [
        {
            "name": "Google Safe Browsing",
            "configured": bool(gsb_key),
            "available": bool(gsb_key),
            "note": "Set GOOGLE_SAFE_BROWSING_API_KEY in .env" if not gsb_key else "Active",
        },
        {
            "name": "VirusTotal",
            "configured": bool(vt_key),
            "available": bool(vt_key),
            "note": "Set VIRUSTOTAL_API_KEY in .env" if not vt_key else "Active",
        },
        {
            "name": "ML Classifier",
            "configured": True,
            "available": True,
            "note": "Local RandomForest model — no API key required",
        },
    ]
    return {"integrations": integrations}


# ---------------------------------------------------------------------------
# Run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
