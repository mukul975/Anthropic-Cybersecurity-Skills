#!/usr/bin/env python3
"""Role Mining for RBAC Optimization Agent - Analyzes access patterns to optimize role-based access control."""

import json
import logging
import argparse
import csv
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def load_entitlements(csv_path):
    """Load user-entitlement assignments from CSV (user,entitlement,system)."""
    assignments = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            assignments.append({"user": row.get("user", "").strip(), "entitlement": row.get("entitlement", "").strip(),
                                "system": row.get("system", "").strip()})
    logger.info("Loaded %d user-entitlement assignments", len(assignments))
    return assignments


def build_user_permission_matrix(assignments):
    """Build user-to-permission-set mapping."""
    matrix = defaultdict(set)
    for a in assignments:
        key = f"{a['system']}:{a['entitlement']}"
        matrix[a["user"]].add(key)
    return {user: sorted(perms) for user, perms in matrix.items()}


def mine_roles_bottom_up(user_matrix, min_users=2):
    """Bottom-up role mining: find common permission sets shared by multiple users."""
    perm_set_users = defaultdict(list)
    for user, perms in user_matrix.items():
        key = tuple(perms)
        perm_set_users[key].append(user)
    candidate_roles = []
    role_id = 0
    for perm_set, users in perm_set_users.items():
        if len(users) >= min_users:
            role_id += 1
            candidate_roles.append({
                "role_id": f"ROLE-{role_id:03d}",
                "permissions": list(perm_set),
                "assigned_users": users,
                "user_count": len(users),
            })
    candidate_roles.sort(key=lambda r: r["user_count"], reverse=True)
    logger.info("Mined %d candidate roles (min_users=%d)", len(candidate_roles), min_users)
    return candidate_roles


def mine_roles_top_down(user_matrix, similarity_threshold=0.8):
    """Top-down role mining: cluster users by permission similarity (Jaccard)."""
    users = list(user_matrix.keys())
    clusters = []
    visited = set()
    for i, u1 in enumerate(users):
        if u1 in visited:
            continue
        cluster = [u1]
        visited.add(u1)
        s1 = set(user_matrix[u1])
        for j in range(i + 1, len(users)):
            u2 = users[j]
            if u2 in visited:
                continue
            s2 = set(user_matrix[u2])
            intersection = len(s1 & s2)
            union = len(s1 | s2)
            jaccard = intersection / union if union > 0 else 0
            if jaccard >= similarity_threshold:
                cluster.append(u2)
                visited.add(u2)
        if len(cluster) >= 2:
            common_perms = set(user_matrix[cluster[0]])
            for u in cluster[1:]:
                common_perms &= set(user_matrix[u])
            clusters.append({"users": cluster, "common_permissions": sorted(common_perms),
                             "user_count": len(cluster)})
    logger.info("Found %d user clusters (threshold=%.2f)", len(clusters), similarity_threshold)
    return clusters


def detect_outliers(user_matrix, candidate_roles):
    """Detect users with unique permissions not covered by any candidate role."""
    role_perms = set()
    for role in candidate_roles:
        role_perms.update(role["permissions"])
    outliers = []
    for user, perms in user_matrix.items():
        uncovered = set(perms) - role_perms
        if uncovered:
            outliers.append({"user": user, "uncovered_permissions": sorted(uncovered),
                             "total_permissions": len(perms), "uncovered_count": len(uncovered)})
    outliers.sort(key=lambda o: o["uncovered_count"], reverse=True)
    logger.info("Found %d users with uncovered permissions", len(outliers))
    return outliers


def calculate_optimization_metrics(user_matrix, candidate_roles):
    """Calculate RBAC optimization metrics."""
    total_assignments = sum(len(perms) for perms in user_matrix.values())
    total_users = len(user_matrix)
    role_assignments = sum(r["user_count"] for r in candidate_roles)
    all_perms = set()
    for perms in user_matrix.values():
        all_perms.update(perms)
    return {
        "total_users": total_users,
        "total_unique_permissions": len(all_perms),
        "total_assignments": total_assignments,
        "candidate_roles": len(candidate_roles),
        "role_coverage_users": role_assignments,
        "avg_permissions_per_user": round(total_assignments / total_users, 1) if total_users else 0,
        "avg_users_per_role": round(role_assignments / len(candidate_roles), 1) if candidate_roles else 0,
    }


def generate_report(candidate_roles, clusters, outliers, metrics):
    """Generate role mining report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "optimization_metrics": metrics,
        "candidate_roles": candidate_roles[:20],
        "user_clusters": clusters[:20],
        "permission_outliers": outliers[:20],
    }
    print(f"RBAC REPORT: {metrics['total_users']} users, {metrics['candidate_roles']} candidate roles, "
          f"{len(outliers)} outliers")
    return report


def main():
    parser = argparse.ArgumentParser(description="Role Mining for RBAC Optimization")
    parser.add_argument("--input", required=True, help="CSV file with user,entitlement,system columns")
    parser.add_argument("--min-users", type=int, default=2, help="Minimum users for role candidate")
    parser.add_argument("--similarity", type=float, default=0.8, help="Jaccard similarity threshold")
    parser.add_argument("--output", default="rbac_mining_report.json")
    args = parser.parse_args()

    assignments = load_entitlements(args.input)
    user_matrix = build_user_permission_matrix(assignments)
    candidate_roles = mine_roles_bottom_up(user_matrix, args.min_users)
    clusters = mine_roles_top_down(user_matrix, args.similarity)
    outliers = detect_outliers(user_matrix, candidate_roles)
    metrics = calculate_optimization_metrics(user_matrix, candidate_roles)
    report = generate_report(candidate_roles, clusters, outliers, metrics)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
