import argparse

from app import create_app
from analytics.traffic_generator import generate_traffic


def main():
    parser = argparse.ArgumentParser(description="Generate Fleuris Vault traffic.")
    parser.add_argument("--scenario", default="mixed", help="Scenario name")
    parser.add_argument("--events", type=int, default=500, help="Number of events")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")
    args = parser.parse_args()

    app = create_app()
    summary = generate_traffic(app, scenario=args.scenario, events=args.events, seed=args.seed)
    print(
        f"Generated {summary['events']} events ({summary['success']} success, {summary['failed']} failed)"
    )


if __name__ == "__main__":
    main()
