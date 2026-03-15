#!/usr/bin/env python3
"""Agent for managing and analyzing anti-phishing training program metrics."""

import json
import argparse
from datetime import datetime
from pathlib import Path

import pandas as pd
import numpy as np


def load_simulation_results(csv_path):
    """Load phishing simulation results CSV."""
    df = pd.read_csv(csv_path, parse_dates=["timestamp"])
    return df


def calculate_department_metrics(df):
    """Calculate phishing susceptibility metrics per department."""
    results = []
    for dept, group in df.groupby("department"):
        total = len(group)
        clicked = group["clicked"].sum()
        submitted = group["submitted_credentials"].sum() if "submitted_credentials" in group.columns else 0
        reported = group["reported"].sum() if "reported" in group.columns else 0
        results.append({
            "department": dept,
            "total_recipients": int(total),
            "click_rate": round(clicked / total * 100, 1) if total > 0 else 0,
            "submission_rate": round(submitted / total * 100, 1) if total > 0 else 0,
            "report_rate": round(reported / total * 100, 1) if total > 0 else 0,
            "risk_level": "HIGH" if clicked / total > 0.3 else "MEDIUM" if clicked / total > 0.15 else "LOW",
        })
    return sorted(results, key=lambda x: x["click_rate"], reverse=True)


def analyze_trend(df):
    """Analyze phishing simulation trends over time."""
    df["month"] = df["timestamp"].dt.to_period("M")
    monthly = df.groupby("month").agg(
        total=("clicked", "count"),
        clicks=("clicked", "sum"),
    ).reset_index()
    monthly["click_rate"] = (monthly["clicks"] / monthly["total"] * 100).round(1)
    monthly["month"] = monthly["month"].astype(str)
    trend = monthly.to_dict(orient="records")
    if len(trend) >= 2:
        first_rate = trend[0]["click_rate"]
        last_rate = trend[-1]["click_rate"]
        improvement = round(first_rate - last_rate, 1)
    else:
        improvement = 0
    return {"monthly_data": trend, "improvement_pct": improvement}


def identify_repeat_clickers(df):
    """Identify users who repeatedly click phishing links."""
    clickers = df[df["clicked"] == True]
    repeat = clickers.groupby("email").agg(
        click_count=("clicked", "sum"),
        department=("department", "first"),
        name=("name", "first") if "name" in df.columns else ("email", "first"),
    ).reset_index()
    repeat = repeat[repeat["click_count"] >= 2].sort_values("click_count", ascending=False)
    return repeat.to_dict(orient="records")


def calculate_training_completion(training_df):
    """Calculate training module completion rates."""
    results = []
    for module, group in training_df.groupby("module_name"):
        total = len(group)
        completed = group["completed"].sum()
        results.append({
            "module": module,
            "enrolled": int(total),
            "completed": int(completed),
            "completion_rate": round(completed / total * 100, 1) if total > 0 else 0,
        })
    return sorted(results, key=lambda x: x["completion_rate"])


def generate_risk_score(dept_metrics):
    """Generate overall organization risk score based on phishing metrics."""
    if not dept_metrics:
        return {"score": 0, "grade": "N/A"}
    avg_click = np.mean([d["click_rate"] for d in dept_metrics])
    avg_report = np.mean([d["report_rate"] for d in dept_metrics])
    score = max(0, 100 - (avg_click * 2) + (avg_report * 0.5))
    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return {
        "score": round(score, 1),
        "grade": grade,
        "avg_click_rate": round(avg_click, 1),
        "avg_report_rate": round(avg_report, 1),
    }


def recommend_training(dept_metrics, repeat_clickers):
    """Generate training recommendations based on metrics."""
    recommendations = []
    high_risk_depts = [d for d in dept_metrics if d["risk_level"] == "HIGH"]
    for dept in high_risk_depts:
        recommendations.append({
            "target": dept["department"],
            "type": "department",
            "action": "Mandatory phishing awareness training",
            "priority": "HIGH",
            "reason": f"Click rate {dept['click_rate']}% exceeds 30% threshold",
        })
    for user in repeat_clickers[:20]:
        recommendations.append({
            "target": user.get("email", ""),
            "type": "individual",
            "action": "One-on-one coaching session",
            "priority": "CRITICAL",
            "reason": f"Clicked {user['click_count']} times across simulations",
        })
    return recommendations


def main():
    parser = argparse.ArgumentParser(description="Anti-Phishing Training Program Agent")
    parser.add_argument("--simulation-csv", help="Phishing simulation results CSV")
    parser.add_argument("--training-csv", help="Training completion CSV")
    parser.add_argument("--output", default="phishing_training_report.json")
    parser.add_argument("--action", choices=[
        "departments", "trends", "repeaters", "completion", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.simulation_csv:
        df = load_simulation_results(args.simulation_csv)
        print(f"[+] Loaded {len(df)} simulation results")

        if args.action in ("departments", "full_analysis"):
            metrics = calculate_department_metrics(df)
            report["findings"]["department_metrics"] = metrics
            report["findings"]["risk_score"] = generate_risk_score(metrics)
            print(f"[+] Departments analyzed: {len(metrics)}")

        if args.action in ("trends", "full_analysis"):
            trend = analyze_trend(df)
            report["findings"]["trend_analysis"] = trend
            print(f"[+] Improvement: {trend['improvement_pct']}%")

        if args.action in ("repeaters", "full_analysis"):
            repeaters = identify_repeat_clickers(df)
            report["findings"]["repeat_clickers"] = repeaters
            print(f"[+] Repeat clickers: {len(repeaters)}")

        if args.action == "full_analysis":
            metrics = report["findings"].get("department_metrics", [])
            repeaters = report["findings"].get("repeat_clickers", [])
            recs = recommend_training(metrics, repeaters)
            report["findings"]["recommendations"] = recs

    if args.training_csv:
        tdf = pd.read_csv(args.training_csv)
        completion = calculate_training_completion(tdf)
        report["findings"]["training_completion"] = completion
        print(f"[+] Training modules: {len(completion)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
