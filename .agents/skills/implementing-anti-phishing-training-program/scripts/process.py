#!/usr/bin/env python3
"""
Anti-Phishing Training Program Analytics

Tracks training completion, simulation results, and program effectiveness
over time. Generates reports comparing departments, identifying repeat
offenders, and measuring ROI.

Usage:
    python process.py dashboard --data program_data.json
    python process.py trend --data program_data.json --months 12
    python process.py repeat-offenders --data program_data.json
    python process.py department-report --data program_data.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from collections import defaultdict
from dataclasses import dataclass, field, asdict


@dataclass
class UserRecord:
    """Training and simulation record for a single user."""
    email: str = ""
    name: str = ""
    department: str = ""
    role: str = ""
    simulations_sent: int = 0
    simulations_clicked: int = 0
    simulations_submitted: int = 0
    simulations_reported: int = 0
    trainings_assigned: int = 0
    trainings_completed: int = 0
    last_simulation_date: str = ""
    last_training_date: str = ""
    risk_level: str = "low"


@dataclass
class DepartmentMetrics:
    """Aggregated metrics for a department."""
    name: str = ""
    total_users: int = 0
    avg_click_rate: float = 0.0
    avg_submit_rate: float = 0.0
    avg_report_rate: float = 0.0
    training_completion: float = 0.0
    repeat_offenders: int = 0
    trend: str = "stable"


@dataclass
class ProgramDashboard:
    """Overall program dashboard metrics."""
    total_users: int = 0
    total_simulations_sent: int = 0
    overall_click_rate: float = 0.0
    overall_submit_rate: float = 0.0
    overall_report_rate: float = 0.0
    training_completion_rate: float = 0.0
    repeat_offender_count: int = 0
    repeat_offender_rate: float = 0.0
    maturity_level: int = 1
    departments: list = field(default_factory=list)
    top_risks: list = field(default_factory=list)
    monthly_trends: list = field(default_factory=list)


def calculate_risk_level(user: UserRecord) -> str:
    """Calculate risk level for a user based on simulation history."""
    if user.simulations_sent == 0:
        return "unknown"

    click_rate = user.simulations_clicked / user.simulations_sent
    submit_rate = user.simulations_submitted / user.simulations_sent

    if submit_rate > 0.3 or user.simulations_submitted >= 3:
        return "critical"
    elif click_rate > 0.4 or user.simulations_clicked >= 3:
        return "high"
    elif click_rate > 0.2:
        return "medium"
    elif user.simulations_reported > 0:
        return "low"
    else:
        return "low"


def assess_maturity(dashboard: ProgramDashboard) -> int:
    """Assess SANS Security Awareness Maturity level (1-5)."""
    if dashboard.total_simulations_sent == 0:
        return 1  # Non-existent

    if dashboard.training_completion_rate < 50:
        return 2  # Compliance-focused

    if dashboard.overall_click_rate > 15:
        return 2

    if dashboard.overall_click_rate > 5:
        return 3  # Promoting Awareness

    if dashboard.overall_report_rate > 50 and dashboard.overall_click_rate < 5:
        return 5  # Metrics Framework

    return 4  # Long-term Sustainment


def process_program_data(data: dict) -> ProgramDashboard:
    """Process raw program data into dashboard metrics."""
    dashboard = ProgramDashboard()

    users_data = data.get("users", [])
    simulations = data.get("simulations", [])
    trainings = data.get("trainings", [])

    # Build user records
    user_records = {}
    for u in users_data:
        record = UserRecord(
            email=u.get("email", ""),
            name=u.get("name", ""),
            department=u.get("department", "Unknown"),
            role=u.get("role", ""),
        )
        user_records[record.email] = record

    # Process simulation results
    for sim in simulations:
        for result in sim.get("results", []):
            email = result.get("email", "")
            if email in user_records:
                user = user_records[email]
                user.simulations_sent += 1
                if result.get("clicked"):
                    user.simulations_clicked += 1
                if result.get("submitted"):
                    user.simulations_submitted += 1
                if result.get("reported"):
                    user.simulations_reported += 1
                user.last_simulation_date = sim.get("date", "")

    # Process training completions
    for training in trainings:
        for completion in training.get("completions", []):
            email = completion.get("email", "")
            if email in user_records:
                user = user_records[email]
                user.trainings_assigned += 1
                if completion.get("completed"):
                    user.trainings_completed += 1
                user.last_training_date = training.get("date", "")

    # Calculate risk levels
    for user in user_records.values():
        user.risk_level = calculate_risk_level(user)

    # Aggregate overall metrics
    all_users = list(user_records.values())
    dashboard.total_users = len(all_users)

    total_sent = sum(u.simulations_sent for u in all_users)
    total_clicked = sum(u.simulations_clicked for u in all_users)
    total_submitted = sum(u.simulations_submitted for u in all_users)
    total_reported = sum(u.simulations_reported for u in all_users)
    total_assigned = sum(u.trainings_assigned for u in all_users)
    total_completed = sum(u.trainings_completed for u in all_users)

    dashboard.total_simulations_sent = total_sent
    dashboard.overall_click_rate = round(total_clicked / max(total_sent, 1) * 100, 1)
    dashboard.overall_submit_rate = round(total_submitted / max(total_sent, 1) * 100, 1)
    dashboard.overall_report_rate = round(total_reported / max(total_sent, 1) * 100, 1)
    dashboard.training_completion_rate = round(total_completed / max(total_assigned, 1) * 100, 1)

    # Repeat offenders (clicked 2+ times)
    repeat_offenders = [u for u in all_users if u.simulations_clicked >= 2]
    dashboard.repeat_offender_count = len(repeat_offenders)
    dashboard.repeat_offender_rate = round(
        len(repeat_offenders) / max(len(all_users), 1) * 100, 1
    )

    # Department breakdown
    dept_users = defaultdict(list)
    for user in all_users:
        dept_users[user.department].append(user)

    for dept_name, users in sorted(dept_users.items()):
        dept = DepartmentMetrics(name=dept_name, total_users=len(users))

        d_sent = sum(u.simulations_sent for u in users)
        d_clicked = sum(u.simulations_clicked for u in users)
        d_submitted = sum(u.simulations_submitted for u in users)
        d_reported = sum(u.simulations_reported for u in users)
        d_assigned = sum(u.trainings_assigned for u in users)
        d_completed = sum(u.trainings_completed for u in users)

        dept.avg_click_rate = round(d_clicked / max(d_sent, 1) * 100, 1)
        dept.avg_submit_rate = round(d_submitted / max(d_sent, 1) * 100, 1)
        dept.avg_report_rate = round(d_reported / max(d_sent, 1) * 100, 1)
        dept.training_completion = round(d_completed / max(d_assigned, 1) * 100, 1)
        dept.repeat_offenders = sum(1 for u in users if u.simulations_clicked >= 2)

        dashboard.departments.append(dept)

    # Top risk users
    risk_users = sorted(all_users, key=lambda u: u.simulations_submitted, reverse=True)
    dashboard.top_risks = [
        {"email": u.email, "name": u.name, "department": u.department,
         "click_count": u.simulations_clicked, "submit_count": u.simulations_submitted,
         "risk_level": u.risk_level}
        for u in risk_users[:20] if u.simulations_clicked > 0
    ]

    # Monthly trends from simulation data
    monthly = defaultdict(lambda: {"sent": 0, "clicked": 0, "submitted": 0, "reported": 0})
    for sim in simulations:
        month = sim.get("date", "")[:7]  # YYYY-MM
        for result in sim.get("results", []):
            monthly[month]["sent"] += 1
            if result.get("clicked"):
                monthly[month]["clicked"] += 1
            if result.get("submitted"):
                monthly[month]["submitted"] += 1
            if result.get("reported"):
                monthly[month]["reported"] += 1

    for month in sorted(monthly.keys()):
        m = monthly[month]
        dashboard.monthly_trends.append({
            "month": month,
            "sent": m["sent"],
            "click_rate": round(m["clicked"] / max(m["sent"], 1) * 100, 1),
            "submit_rate": round(m["submitted"] / max(m["sent"], 1) * 100, 1),
            "report_rate": round(m["reported"] / max(m["sent"], 1) * 100, 1),
        })

    dashboard.maturity_level = assess_maturity(dashboard)

    return dashboard


def format_dashboard(dashboard: ProgramDashboard) -> str:
    """Format dashboard as text report."""
    lines = []
    lines.append("=" * 65)
    lines.append("  ANTI-PHISHING TRAINING PROGRAM DASHBOARD")
    lines.append("=" * 65)
    lines.append(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"  Maturity Level: {dashboard.maturity_level}/5 (SANS Model)")
    lines.append("")

    lines.append("[PROGRAM OVERVIEW]")
    lines.append(f"  Total Users:              {dashboard.total_users}")
    lines.append(f"  Total Simulations Sent:   {dashboard.total_simulations_sent}")
    lines.append(f"  Overall Click Rate:       {dashboard.overall_click_rate}%")
    lines.append(f"  Overall Submit Rate:      {dashboard.overall_submit_rate}%")
    lines.append(f"  Overall Report Rate:      {dashboard.overall_report_rate}%")
    lines.append(f"  Training Completion:      {dashboard.training_completion_rate}%")
    lines.append(f"  Repeat Offenders:         {dashboard.repeat_offender_count} "
                 f"({dashboard.repeat_offender_rate}%)")
    lines.append("")

    lines.append("[DEPARTMENT BREAKDOWN]")
    lines.append(f"  {'Department':<20} {'Users':>6} {'Click%':>7} {'Submit%':>8} "
                 f"{'Report%':>8} {'Training%':>10} {'Repeat':>7}")
    lines.append("  " + "-" * 66)
    for dept in sorted(dashboard.departments, key=lambda d: d.avg_click_rate, reverse=True):
        lines.append(f"  {dept.name:<20} {dept.total_users:>6} {dept.avg_click_rate:>6.1f}% "
                     f"{dept.avg_submit_rate:>7.1f}% {dept.avg_report_rate:>7.1f}% "
                     f"{dept.training_completion:>9.1f}% {dept.repeat_offenders:>7}")
    lines.append("")

    if dashboard.top_risks:
        lines.append("[TOP RISK USERS]")
        for i, user in enumerate(dashboard.top_risks[:10], 1):
            lines.append(f"  {i}. {user['name']} ({user['department']}) - "
                         f"Clicked: {user['click_count']}, Submitted: {user['submit_count']} "
                         f"[{user['risk_level'].upper()}]")
        lines.append("")

    if dashboard.monthly_trends:
        lines.append("[MONTHLY TRENDS]")
        lines.append(f"  {'Month':<10} {'Sent':>6} {'Click%':>7} {'Submit%':>8} {'Report%':>8}")
        lines.append("  " + "-" * 39)
        for trend in dashboard.monthly_trends[-12:]:
            lines.append(f"  {trend['month']:<10} {trend['sent']:>6} "
                         f"{trend['click_rate']:>6.1f}% {trend['submit_rate']:>7.1f}% "
                         f"{trend['report_rate']:>7.1f}%")

    lines.append("")
    lines.append("=" * 65)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Anti-Phishing Training Program Analytics")
    subparsers = parser.add_subparsers(dest="command")

    dash_parser = subparsers.add_parser("dashboard", help="Generate program dashboard")
    dash_parser.add_argument("--data", required=True, help="Program data JSON file")
    dash_parser.add_argument("--output", "-o", help="Output file")

    dept_parser = subparsers.add_parser("department-report", help="Department breakdown")
    dept_parser.add_argument("--data", required=True)

    repeat_parser = subparsers.add_parser("repeat-offenders", help="List repeat offenders")
    repeat_parser.add_argument("--data", required=True)
    repeat_parser.add_argument("--threshold", type=int, default=2, help="Minimum click count")

    trend_parser = subparsers.add_parser("trend", help="Show monthly trends")
    trend_parser.add_argument("--data", required=True)
    trend_parser.add_argument("--months", type=int, default=12)

    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    with open(args.data, "r") as f:
        data = json.load(f)

    dashboard = process_program_data(data)

    if args.command == "dashboard":
        if args.json:
            output = json.dumps(asdict(dashboard), indent=2, default=str)
        else:
            output = format_dashboard(dashboard)

        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Dashboard written to {args.output}")
        else:
            print(output)

    elif args.command == "department-report":
        for dept in sorted(dashboard.departments, key=lambda d: d.avg_click_rate, reverse=True):
            if args.json:
                print(json.dumps(asdict(dept), indent=2))
            else:
                print(f"{dept.name}: {dept.total_users} users, "
                      f"click={dept.avg_click_rate}%, report={dept.avg_report_rate}%, "
                      f"training={dept.training_completion}%")

    elif args.command == "repeat-offenders":
        for user in dashboard.top_risks:
            if user["click_count"] >= args.threshold:
                print(f"  {user['name']} ({user['department']}): "
                      f"clicked {user['click_count']}x, submitted {user['submit_count']}x "
                      f"[{user['risk_level']}]")

    elif args.command == "trend":
        for trend in dashboard.monthly_trends[-args.months:]:
            print(f"  {trend['month']}: click={trend['click_rate']}%, "
                  f"submit={trend['submit_rate']}%, report={trend['report_rate']}%")


if __name__ == "__main__":
    main()
