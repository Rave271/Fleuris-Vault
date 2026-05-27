from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from ..services.auth import generate_csrf_token, login_required, require_csrf_token
from ..services.security import log_event
from src.analytics.traffic_generator import generate_traffic

traffic_bp = Blueprint("traffic", __name__)


@traffic_bp.route("/traffic-generator", methods=["GET", "POST"])
def traffic_generator():
    user = login_required()
    if not user:
        return redirect(url_for("auth.login"))
    if user.role != "admin":
        log_event(current_app.logger, "ACCESS_DENIED", "Non-admin attempted to view traffic generator", user.id)
        return render_template(
            "error.html",
            title="Access denied",
            message="You do not have permission to open that page or perform that action.",
        ), 403

    summary = None
    if request.method == "POST":
        require_csrf_token(current_app.logger, request.form.get("csrf_token"))

        scenario = request.form.get("scenario", "mixed")
        try:
            events = int(request.form.get("events", "50"))
        except ValueError:
            events = 50

        summary = generate_traffic(
            current_app._get_current_object(),
            scenario=scenario,
            events=events,
            delay_range_ms=(0, 80),
        )
        flash("Traffic generation completed.", "success")
        return render_template(
            "traffic_generator.html",
            summary=summary,
            csrf_token=generate_csrf_token(),
        )

    return render_template("traffic_generator.html", summary=summary, csrf_token=generate_csrf_token())
