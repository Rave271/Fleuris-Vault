import random
import time
from datetime import datetime

from src.app.extensions import db
from src.app.models import AnalyticsTrafficRun, User


SCENARIOS = {
    "login": "Login traffic",
    "transfer": "Transfer activity",
    "mixed": "Mixed application traffic",
    "failed_login": "Failed login bursts",
    "dashboard": "Heavy dashboard usage",
    "random": "Randomized traffic simulations",
}


def _login(client, username, password, mfa_code=""):
    return client.post(
        "/login",
        data={"username": username, "password": password, "mfa_code": mfa_code},
        follow_redirects=True,
    )


def _logout(client):
    return client.get("/logout", follow_redirects=True)


def _transfer(client, to_user_id, amount, description=""):
    client.get("/transfer")
    with client.session_transaction() as session:
        csrf_token = session.get("csrf_token")
    return client.post(
        "/transfer",
        data={
            "csrf_token": csrf_token,
            "action": "submit",
            "to_account": str(to_user_id),
            "amount": str(amount),
            "description": description,
        },
        follow_redirects=True,
    )


def _dashboard(client):
    return client.get("/dashboard", follow_redirects=True)


def generate_traffic(app, scenario="mixed", events=50, delay_range_ms=(0, 80), seed=None):
    if seed is not None:
        random.seed(seed)

    scenario_key = scenario if scenario in SCENARIOS else "mixed"
    delay_min, delay_max = delay_range_ms
    summary = {
        "scenario": scenario_key,
        "events": events,
        "success": 0,
        "failed": 0,
        "started_at": datetime.utcnow(),
        "finished_at": None,
    }

    with app.app_context():
        customers = User.query.filter_by(role="customer").all()

    if not customers:
        summary["failed"] = events
        summary["finished_at"] = datetime.utcnow()
        return summary

    def sleep_random():
        if delay_max > 0:
            time.sleep(random.randint(delay_min, delay_max) / 1000)

    with app.test_client() as client:
        for _ in range(events):
            try:
                if scenario_key in ("random", "mixed"):
                    action = random.choice(["login", "transfer", "dashboard", "failed_login"])
                else:
                    action = scenario_key

                if action == "login":
                    user = random.choice(customers)
                    _login(client, user.username, "pass")
                    _logout(client)
                elif action == "transfer":
                    sender = random.choice(customers)
                    recipient = random.choice([u for u in customers if u.id != sender.id])
                    _login(client, sender.username, "pass")
                    _transfer(client, recipient.id, random.randint(5, 250), "Ops simulation")
                    _logout(client)
                elif action == "dashboard":
                    user = random.choice(customers)
                    _login(client, user.username, "pass")
                    _dashboard(client)
                    _logout(client)
                elif action == "failed_login":
                    username = random.choice(customers).username
                    _login(client, username, "wrong-pass")

                summary["success"] += 1
            except Exception:
                summary["failed"] += 1
            sleep_random()

    summary["finished_at"] = datetime.utcnow()

    with app.app_context():
        run = AnalyticsTrafficRun(
            scenario=summary["scenario"],
            total_events=summary["events"],
            success_events=summary["success"],
            failed_events=summary["failed"],
            started_at=summary["started_at"],
            finished_at=summary["finished_at"],
        )
        db.session.add(run)
        db.session.commit()

    return summary
