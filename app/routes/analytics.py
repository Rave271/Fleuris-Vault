import os
import subprocess
import sys

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from sqlalchemy import func

from ..models import (
    AnalyticsEndpointPopularity,
    AnalyticsLoginSummary,
    AnalyticsResponseTime,
    AnalyticsTrafficRun,
    AnalyticsUserActivity,
)
from ..services.auth import generate_csrf_token, login_required, require_csrf_token
from ..services.security import log_event

analytics_bp = Blueprint("analytics", __name__)

SPARK_JOBS = {
    "endpoint_popularity": "endpoint_popularity.py",
    "login_analytics": "login_analytics.py",
    "response_time_analytics": "response_time_analytics.py",
    "user_activity_summary": "user_activity_summary.py",
}


def _run_spark_job(job_key):
    script_name = SPARK_JOBS.get(job_key)
    if not script_name:
        return False, f"Unknown job: {job_key}"

    repo_root = os.path.abspath(os.path.join(current_app.root_path, "..", ".."))
    spark_dir = os.path.join(repo_root, "spark_jobs")
    script_path = os.path.join(spark_dir, script_name)

    env = os.environ.copy()
    db_url = current_app.config.get("SQLALCHEMY_DATABASE_URI")
    if db_url:
        env["DATABASE_URL"] = db_url  # always override; shell env may have stale jdbc: value

    log_path = env.get("LOG_PATH") or current_app.config.get("LOG_PATH", "logs/app.json.log")
    if not os.path.isabs(log_path):
        log_path = os.path.join(repo_root, log_path)
    env["LOG_PATH"] = log_path
    env["PYSPARK_PYTHON"] = sys.executable

    try:
        result = subprocess.run(
            [sys.executable, script_path],
            cwd=spark_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"{job_key} timed out"

    if result.returncode != 0:
        stderr = result.stderr or ""
        stdout = result.stdout or ""

        # Extract the root Java exception (first "Caused by:" or the Py4J error line)
        root_cause = ""
        for line in stderr.splitlines():
            stripped = line.strip()
            if stripped.startswith("java.lang.") or stripped.startswith("Caused by:") or stripped.startswith("py4j.protocol.Py4JJavaError"):
                root_cause = stripped
                break

        # Also grab the Python traceback lines (everything after "Traceback")
        python_tb_lines = []
        in_tb = False
        for line in stderr.splitlines():
            if line.startswith("Traceback"):
                in_tb = True
            if in_tb:
                python_tb_lines.append(line)
            # Stop at first blank line after we started collecting
            if in_tb and line.strip() == "" and len(python_tb_lines) > 2:
                break

        if root_cause:
            detail = root_cause
            if python_tb_lines:
                # Show the last 3 python tb lines + root cause
                detail = "\n".join(python_tb_lines[-3:]) + "\n" + root_cause
        else:
            # Fallback: last 10 non-empty lines from combined output
            combined = [l for l in (stderr + "\n" + stdout).splitlines() if l.strip()]
            detail = "\n".join(combined[-10:]).strip() or "Job failed with no output"

        return False, f"{job_key} failed: {detail}"

    return True, f"{job_key} completed"


@analytics_bp.route("/analytics")
def analytics_dashboard():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Non-admin attempted to view analytics", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    endpoint_popularity = AnalyticsEndpointPopularity.query.order_by(
        AnalyticsEndpointPopularity.total_hits.desc()
    ).limit(8).all()
    total_requests = (
        AnalyticsEndpointPopularity.query.with_entities(func.coalesce(func.sum(AnalyticsEndpointPopularity.total_hits), 0))
        .scalar()
    )
    login_summary = AnalyticsLoginSummary.query.order_by(
        AnalyticsLoginSummary.total_count.desc()
    ).all()
    response_times = AnalyticsResponseTime.query.order_by(
        AnalyticsResponseTime.avg_response_ms.desc()
    ).limit(8).all()
    user_activity = AnalyticsUserActivity.query.order_by(
        AnalyticsUserActivity.total_requests.desc()
    ).limit(8).all()
    traffic_runs = AnalyticsTrafficRun.query.order_by(
        AnalyticsTrafficRun.started_at.desc()
    ).limit(6).all()

    return render_template(
        "analytics.html",
        total_requests=total_requests or 0,
        endpoint_popularity=endpoint_popularity,
        login_summary=login_summary,
        response_times=response_times,
        user_activity=user_activity,
        traffic_runs=traffic_runs,
        csrf_token=generate_csrf_token(),
    )


@analytics_bp.route("/analytics/run-job", methods=["POST"])
def run_analytics_job():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Non-admin attempted to run analytics jobs", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    require_csrf_token(current_app.logger, request.form.get("csrf_token"))

    job_key = request.form.get("job", "")
    if job_key == "all":
        failures = []
        for key in SPARK_JOBS:
            ok, message = _run_spark_job(key)
            if not ok:
                failures.append(message)
        if failures:
            flash("; ".join(failures), "error")
        else:
            flash("All analytics jobs completed.", "success")
        return redirect(url_for("analytics.analytics_dashboard"))

    ok, message = _run_spark_job(job_key)
    flash(message, "success" if ok else "error")
    return redirect(url_for("analytics.analytics_dashboard"))
