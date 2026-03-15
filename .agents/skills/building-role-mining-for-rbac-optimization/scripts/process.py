#!/usr/bin/env python3
"""
Role Mining Engine for RBAC Optimization

Implements multiple role mining algorithms (clustering, FCA) on user-permission
assignment data to discover optimal RBAC roles. Generates role definitions,
coverage reports, and migration plans.

Requirements:
    pip install pandas numpy scikit-learn
"""

import csv
import json
from collections import defaultdict
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import silhouette_score


class RoleMiningEngine:
    """Core role mining engine supporting multiple algorithms."""

    def __init__(self, assignments_file=None):
        self.upa_matrix = None
        self.user_metadata = {}
        self.mined_roles = {}

        if assignments_file:
            self.load_assignments(assignments_file)

    def load_assignments(self, filepath):
        """Load user-permission assignments from CSV (user_id, permission_id)."""
        df = pd.read_csv(filepath)
        required = {"user_id", "permission_id"}
        if not required.issubset(df.columns):
            raise ValueError(f"CSV must contain columns: {required}")

        self.upa_matrix = df.pivot_table(
            index="user_id", columns="permission_id",
            aggfunc="size", fill_value=0
        )
        self.upa_matrix = (self.upa_matrix > 0).astype(int)

        print(f"[OK] Loaded UPA matrix: {self.upa_matrix.shape[0]} users x "
              f"{self.upa_matrix.shape[1]} permissions")
        print(f"     Total assignments: {self.upa_matrix.values.sum()}")
        density = self.upa_matrix.values.sum() / self.upa_matrix.size
        print(f"     Matrix density: {density:.2%}")

    def load_user_metadata(self, filepath):
        """Load user HR data (user_id, department, title, location)."""
        df = pd.read_csv(filepath)
        for _, row in df.iterrows():
            self.user_metadata[row["user_id"]] = row.to_dict()

    def find_optimal_k(self, max_k=50):
        """Determine optimal number of roles using silhouette analysis."""
        if self.upa_matrix is None:
            raise ValueError("No data loaded")

        matrix = self.upa_matrix.values
        max_k = min(max_k, matrix.shape[0] - 1)
        scores = []

        for k in range(2, max_k + 1):
            clustering = AgglomerativeClustering(
                n_clusters=k, metric="jaccard", linkage="average"
            )
            labels = clustering.fit_predict(matrix)
            score = silhouette_score(matrix, labels, metric="jaccard")
            scores.append({"k": k, "silhouette": round(score, 4)})

        best = max(scores, key=lambda x: x["silhouette"])
        print(f"[OK] Optimal k={best['k']} (silhouette={best['silhouette']})")
        return best["k"], scores

    def mine_roles_clustering(self, n_clusters=None, threshold=0.8):
        """Mine roles using hierarchical clustering with Jaccard distance."""
        if self.upa_matrix is None:
            raise ValueError("No data loaded")

        if n_clusters is None:
            n_clusters, _ = self.find_optimal_k()

        matrix = self.upa_matrix.values
        clustering = AgglomerativeClustering(
            n_clusters=n_clusters, metric="jaccard", linkage="average"
        )
        labels = clustering.fit_predict(matrix)

        roles = {}
        for cluster_id in range(n_clusters):
            mask = labels == cluster_id
            cluster_users = self.upa_matrix.index[mask].tolist()
            cluster_data = self.upa_matrix.loc[cluster_users]

            perm_freq = cluster_data.mean()
            core_perms = perm_freq[perm_freq >= threshold].index.tolist()

            # Determine role name from user metadata
            role_label = f"Role_{cluster_id:03d}"
            if self.user_metadata:
                depts = [self.user_metadata.get(u, {}).get("department", "Unknown")
                         for u in cluster_users]
                dept_counts = defaultdict(int)
                for d in depts:
                    dept_counts[d] += 1
                if dept_counts:
                    dominant_dept = max(dept_counts, key=dept_counts.get)
                    role_label = f"{dominant_dept}_Role_{cluster_id:03d}"

            roles[role_label] = {
                "permissions": core_perms,
                "user_count": len(cluster_users),
                "users": cluster_users,
                "permission_count": len(core_perms),
            }

        self.mined_roles = roles
        print(f"[OK] Mined {len(roles)} roles via clustering")
        return roles

    def mine_roles_intersection(self, min_users=3):
        """Mine roles by finding common permission intersections."""
        if self.upa_matrix is None:
            raise ValueError("No data loaded")

        user_perm_sets = {}
        for user in self.upa_matrix.index:
            perms = set(self.upa_matrix.columns[self.upa_matrix.loc[user] == 1])
            user_perm_sets[user] = perms

        # Find unique permission sets shared by multiple users
        perm_set_users = defaultdict(list)
        for user, perms in user_perm_sets.items():
            key = frozenset(perms)
            perm_set_users[key].append(user)

        roles = {}
        role_idx = 0
        for perm_set, users in perm_set_users.items():
            if len(users) >= min_users:
                roles[f"ExactRole_{role_idx:03d}"] = {
                    "permissions": sorted(perm_set),
                    "user_count": len(users),
                    "users": users,
                    "permission_count": len(perm_set),
                }
                role_idx += 1

        self.mined_roles = roles
        print(f"[OK] Mined {len(roles)} exact-match roles "
              f"(min {min_users} users per role)")
        return roles

    def evaluate_roles(self, roles=None):
        """Calculate quality metrics for a set of mined roles."""
        if roles is None:
            roles = self.mined_roles
        if not roles:
            return {"error": "No roles to evaluate"}

        total_assignments = int(self.upa_matrix.values.sum())
        covered = 0
        extra = 0

        for role_data in roles.values():
            role_perms = set(role_data["permissions"])
            for user in role_data["users"]:
                user_perms = set(
                    self.upa_matrix.columns[self.upa_matrix.loc[user] == 1]
                )
                covered += len(role_perms & user_perms)
                extra += len(role_perms - user_perms)

        total_role_assignments = sum(
            r["user_count"] + r["permission_count"] for r in roles.values()
        )

        metrics = {
            "total_roles": len(roles),
            "total_original_assignments": total_assignments,
            "covered_assignments": covered,
            "extra_permissions_granted": extra,
            "coverage_rate": round(covered / total_assignments, 4) if total_assignments else 0,
            "deviation_rate": round(extra / (covered + extra), 4) if (covered + extra) else 0,
            "wsc": total_role_assignments + len(roles),
            "avg_permissions_per_role": round(
                np.mean([r["permission_count"] for r in roles.values()]), 1
            ),
            "avg_users_per_role": round(
                np.mean([r["user_count"] for r in roles.values()]), 1
            ),
        }
        return metrics

    def export_roles(self, output_path):
        """Export mined roles to JSON for import into IGA platform."""
        export = {
            "generated_at": pd.Timestamp.now().isoformat(),
            "metrics": self.evaluate_roles(),
            "roles": {}
        }

        for name, data in self.mined_roles.items():
            export["roles"][name] = {
                "name": name,
                "permissions": data["permissions"],
                "user_count": data["user_count"],
                "permission_count": data["permission_count"],
            }

        with open(output_path, "w") as f:
            json.dump(export, f, indent=2)
        print(f"[OK] Exported {len(self.mined_roles)} roles to {output_path}")

    def generate_migration_plan(self, output_path):
        """Generate a CSV migration plan mapping users to new roles."""
        rows = []
        for role_name, role_data in self.mined_roles.items():
            for user in role_data["users"]:
                rows.append({
                    "user_id": user,
                    "new_role": role_name,
                    "permissions_in_role": len(role_data["permissions"]),
                    "current_permissions": int(self.upa_matrix.loc[user].sum()),
                })

        df = pd.DataFrame(rows)
        df.to_csv(output_path, index=False)
        print(f"[OK] Migration plan exported to {output_path}")


if __name__ == "__main__":
    print("=" * 60)
    print("Role Mining Engine for RBAC Optimization")
    print("=" * 60)
    print()
    print("Usage:")
    print("  engine = RoleMiningEngine('user_permissions.csv')")
    print("  engine.load_user_metadata('hr_data.csv')")
    print("  optimal_k, scores = engine.find_optimal_k()")
    print("  roles = engine.mine_roles_clustering(n_clusters=optimal_k)")
    print("  metrics = engine.evaluate_roles()")
    print("  engine.export_roles('mined_roles.json')")
    print("  engine.generate_migration_plan('migration_plan.csv')")
