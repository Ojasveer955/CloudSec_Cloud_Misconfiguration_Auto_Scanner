# db/dao.py
from db.models import SessionLocal, Run, Finding, init_db
from datetime import datetime
import json

init_db()


def start_run():
    db = SessionLocal()
    run = Run(status="running")
    db.add(run)
    db.commit()
    db.refresh(run)
    db.close()
    return run.id


def save_findings(run_id, findings):
    db = SessionLocal()
    for f in findings:
        record = Finding(
            run_id=run_id,
            rule_id=f.get("rule_id"),
            service=f.get("service"),
            resource_id=f.get("resource_id"),
            title=f.get("title"),
            severity=f.get("severity"),
            evidence=json.dumps(f.get("evidence", {})),
            remediation=json.dumps(f.get("remediation", [])),
        )
        db.add(record)
    db.commit()
    db.close()


def finish_run(run_id):
    db = SessionLocal()
    run = db.query(Run).filter(Run.id == run_id).first()
    if run:
        run.status = "finished"
        run.finished_at = datetime.utcnow()
        db.commit()
    db.close()


def get_all_findings():
    db = SessionLocal()
    rows = db.query(Finding).all()
    results = []
    for r in rows:
        results.append(
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "service": r.service,
                "title": r.title,
                "severity": r.severity,
                "resource_id": r.resource_id,
                "evidence": r.evidence,
                "remediation": r.remediation,
            }
        )
    db.close()
    return results


def get_findings_by_run(run_id):
    db = SessionLocal()
    rows = db.query(Finding).filter(Finding.run_id == run_id).all()
    results = []
    for r in rows:
        results.append(
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "service": r.service,
                "title": r.title,
                "severity": r.severity,
                "resource_id": r.resource_id,
                "evidence": r.evidence,
                "remediation": r.remediation,
            }
        )
    db.close()
    return results


def get_all_runs():
    db = SessionLocal()
    rows = db.query(Run).all()
    results = []
    for r in rows:
        results.append(
            {
                "id": r.id,
                "status": r.status,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
            }
        )
    db.close()
    return results


def get_findings_trend():
    """Return a list of runs with count of findings."""
    db = SessionLocal()
    rows = db.query(Run.id, Run.started_at, Run.finished_at, Run.status).all()

    results = []
    for r in rows:
        count = db.query(Finding).filter(Finding.run_id == r.id).count()
        results.append(
            {
                "run_id": r.id,
                "started_at": r.started_at,
                "status": r.status,
                "findings": count,
            }
        )
    db.close()
    return results
