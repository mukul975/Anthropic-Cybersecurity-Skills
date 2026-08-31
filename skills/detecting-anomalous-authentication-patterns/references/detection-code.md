# Authentication Anomaly Detection Code

Reference implementations for the workflow in `SKILL.md`. Each section corresponds to a workflow step.

## Step 1: Collect and Normalize Authentication Logs

```python
import pandas as pd
import json
from datetime import datetime, timedelta
from collections import defaultdict

# Parse authentication logs from multiple sources
def normalize_auth_logs(log_source, raw_logs):
    """Normalize authentication events to a common schema."""
    normalized = []

    for event in raw_logs:
        if log_source == "azure_ad":
            normalized.append({
                "timestamp": event["createdDateTime"],
                "user": event["userPrincipalName"],
                "source_ip": event["ipAddress"],
                "location": {
                    "city": event.get("location", {}).get("city"),
                    "state": event.get("location", {}).get("state"),
                    "country": event.get("location", {}).get("countryOrRegion"),
                    "lat": event.get("location", {}).get("geoCoordinates", {}).get("latitude"),
                    "lon": event.get("location", {}).get("geoCoordinates", {}).get("longitude")
                },
                "result": "success" if event["status"]["errorCode"] == 0 else "failure",
                "failure_reason": event["status"].get("failureReason", ""),
                "app": event.get("appDisplayName", "Unknown"),
                "device": event.get("deviceDetail", {}).get("operatingSystem", "Unknown"),
                "browser": event.get("deviceDetail", {}).get("browser", "Unknown"),
                "mfa_result": event.get("authenticationDetails", [{}])[0].get("succeeded", None),
                "risk_level": event.get("riskLevelDuringSignIn", "none"),
                "client_app": event.get("clientAppUsed", "Unknown"),
                "source": "azure_ad"
            })
        elif log_source == "okta":
            normalized.append({
                "timestamp": event["published"],
                "user": event["actor"]["alternateId"],
                "source_ip": event["client"]["ipAddress"],
                "location": {
                    "city": event["client"].get("geographicalContext", {}).get("city"),
                    "state": event["client"].get("geographicalContext", {}).get("state"),
                    "country": event["client"].get("geographicalContext", {}).get("country"),
                    "lat": event["client"].get("geographicalContext", {}).get("geolocation", {}).get("lat"),
                    "lon": event["client"].get("geographicalContext", {}).get("geolocation", {}).get("lon")
                },
                "result": "success" if event["outcome"]["result"] == "SUCCESS" else "failure",
                "failure_reason": event["outcome"].get("reason", ""),
                "app": event.get("target", [{}])[0].get("displayName", "Unknown"),
                "device": event["client"].get("device", "Unknown"),
                "browser": event["client"].get("userAgent", {}).get("browser", "Unknown"),
                "source": "okta"
            })
        elif log_source == "windows_ad":
            normalized.append({
                "timestamp": event["TimeCreated"],
                "user": event["TargetUserName"],
                "source_ip": event.get("IpAddress", ""),
                "location": None,  # Requires GeoIP enrichment
                "result": "success" if event["EventId"] in [4624, 4648] else "failure",
                "failure_reason": event.get("FailureReason", ""),
                "logon_type": event.get("LogonType", ""),
                "source": "windows_ad"
            })

    return pd.DataFrame(normalized)

# Enrich with GeoIP data for Windows AD logs missing location
import geoip2.database

def enrich_geoip(df, geoip_db_path="/opt/geoip/GeoLite2-City.mmdb"):
    """Add geolocation data to events missing location information."""
    reader = geoip2.database.Reader(geoip_db_path)

    for idx, row in df.iterrows():
        if row["location"] is None and row["source_ip"]:
            try:
                response = reader.city(row["source_ip"])
                df.at[idx, "location"] = {
                    "city": response.city.name,
                    "country": response.country.iso_code,
                    "lat": response.location.latitude,
                    "lon": response.location.longitude
                }
            except Exception:
                pass

    reader.close()
    return df
```

## Step 2: Detect Impossible Travel Anomalies

```python
from math import radians, sin, cos, sqrt, atan2
from datetime import datetime

def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate great-circle distance between two points in km."""
    R = 6371  # Earth's radius in kilometers

    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))

    return R * c

def detect_impossible_travel(df, max_speed_kmh=900):
    """
    Detect impossible travel events where a user authenticates from
    two locations faster than physically possible.

    max_speed_kmh: Maximum realistic travel speed (900 km/h ~= commercial flight)
    """
    alerts = []

    # Sort by user and timestamp
    df_sorted = df.sort_values(["user", "timestamp"])

    for user, user_events in df_sorted.groupby("user"):
        successful_events = user_events[user_events["result"] == "success"]

        for i in range(1, len(successful_events)):
            prev = successful_events.iloc[i-1]
            curr = successful_events.iloc[i]

            # Skip if location data is missing
            if not prev.get("location") or not curr.get("location"):
                continue
            if not prev["location"].get("lat") or not curr["location"].get("lat"):
                continue

            # Calculate distance and time delta
            distance_km = haversine_distance(
                prev["location"]["lat"], prev["location"]["lon"],
                curr["location"]["lat"], curr["location"]["lon"]
            )

            time_diff = (pd.Timestamp(curr["timestamp"]) -
                        pd.Timestamp(prev["timestamp"])).total_seconds() / 3600

            if time_diff <= 0:
                continue

            required_speed = distance_km / time_diff

            # Flag if required speed exceeds maximum realistic travel
            if required_speed > max_speed_kmh and distance_km > 100:
                alerts.append({
                    "alert_type": "IMPOSSIBLE_TRAVEL",
                    "severity": "HIGH",
                    "user": user,
                    "timestamp": curr["timestamp"],
                    "details": {
                        "location_1": f"{prev['location']['city']}, {prev['location']['country']}",
                        "location_2": f"{curr['location']['city']}, {curr['location']['country']}",
                        "time_1": prev["timestamp"],
                        "time_2": curr["timestamp"],
                        "distance_km": round(distance_km, 1),
                        "time_hours": round(time_diff, 2),
                        "required_speed_kmh": round(required_speed, 1),
                        "source_ip_1": prev["source_ip"],
                        "source_ip_2": curr["source_ip"]
                    }
                })

    return alerts

# Run impossible travel detection
travel_alerts = detect_impossible_travel(auth_df)
print(f"Impossible travel alerts: {len(travel_alerts)}")
for alert in travel_alerts:
    print(f"  [{alert['severity']}] {alert['user']}: "
          f"{alert['details']['location_1']} -> {alert['details']['location_2']} "
          f"({alert['details']['distance_km']} km in {alert['details']['time_hours']}h)")
```

## Step 3: Detect Brute Force and Password Spraying

```python
from collections import Counter

def detect_brute_force(df, threshold_failures=10, window_minutes=10):
    """
    Detect brute force attacks: many failed attempts against
    a single account in a short time window.
    """
    alerts = []
    failed = df[df["result"] == "failure"].copy()
    failed["timestamp"] = pd.to_datetime(failed["timestamp"])

    for user, user_fails in failed.groupby("user"):
        user_fails_sorted = user_fails.sort_values("timestamp")

        # Sliding window analysis
        for i, row in user_fails_sorted.iterrows():
            window_start = row["timestamp"]
            window_end = window_start + timedelta(minutes=window_minutes)

            window_events = user_fails_sorted[
                (user_fails_sorted["timestamp"] >= window_start) &
                (user_fails_sorted["timestamp"] <= window_end)
            ]

            if len(window_events) >= threshold_failures:
                source_ips = window_events["source_ip"].unique()
                alerts.append({
                    "alert_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "user": user,
                    "timestamp": str(window_start),
                    "details": {
                        "failed_attempts": len(window_events),
                        "window_minutes": window_minutes,
                        "source_ips": list(source_ips),
                        "distributed": len(source_ips) > 1,
                        "failure_reasons": dict(Counter(window_events["failure_reason"]))
                    }
                })
                break  # One alert per user per detection pass

    return alerts

def detect_password_spray(df, threshold_users=10, window_minutes=30):
    """
    Detect password spraying: failed logins against many different
    accounts from the same source in a short window (1-2 attempts per user).
    """
    alerts = []
    failed = df[df["result"] == "failure"].copy()
    failed["timestamp"] = pd.to_datetime(failed["timestamp"])

    for source_ip, ip_events in failed.groupby("source_ip"):
        ip_events_sorted = ip_events.sort_values("timestamp")

        for i, row in ip_events_sorted.iterrows():
            window_start = row["timestamp"]
            window_end = window_start + timedelta(minutes=window_minutes)

            window_events = ip_events_sorted[
                (ip_events_sorted["timestamp"] >= window_start) &
                (ip_events_sorted["timestamp"] <= window_end)
            ]

            unique_users = window_events["user"].nunique()
            attempts_per_user = len(window_events) / unique_users if unique_users > 0 else 0

            # Password spray: many users targeted, few attempts per user
            if unique_users >= threshold_users and attempts_per_user <= 3:
                # Check if any succeeded (compromised account)
                success_after = df[
                    (df["source_ip"] == source_ip) &
                    (df["result"] == "success") &
                    (pd.to_datetime(df["timestamp"]) > window_start) &
                    (pd.to_datetime(df["timestamp"]) < window_end + timedelta(hours=1))
                ]

                alerts.append({
                    "alert_type": "PASSWORD_SPRAY",
                    "severity": "CRITICAL" if len(success_after) > 0 else "HIGH",
                    "timestamp": str(window_start),
                    "details": {
                        "source_ip": source_ip,
                        "targeted_users": unique_users,
                        "total_attempts": len(window_events),
                        "avg_attempts_per_user": round(attempts_per_user, 1),
                        "window_minutes": window_minutes,
                        "successful_logins_after": len(success_after),
                        "compromised_accounts": list(success_after["user"].unique()) if len(success_after) > 0 else []
                    }
                })
                break

    return alerts

# Run detections
brute_force_alerts = detect_brute_force(auth_df)
spray_alerts = detect_password_spray(auth_df)
print(f"Brute force alerts: {len(brute_force_alerts)}")
print(f"Password spray alerts: {len(spray_alerts)}")
```

## Step 4: Build Behavioral Baselines and Detect Deviations

```python
import numpy as np
from scipy import stats
from sklearn.ensemble import IsolationForest

def build_user_baseline(df, user, lookback_days=90):
    """Build behavioral baseline for a specific user."""
    user_events = df[df["user"] == user].copy()
    user_events["timestamp"] = pd.to_datetime(user_events["timestamp"])
    user_events["hour"] = user_events["timestamp"].dt.hour
    user_events["day_of_week"] = user_events["timestamp"].dt.dayofweek

    baseline = {
        "user": user,
        "typical_hours": {
            "start": int(user_events["hour"].quantile(0.05)),
            "end": int(user_events["hour"].quantile(0.95)),
            "mean": float(user_events["hour"].mean()),
            "std": float(user_events["hour"].std())
        },
        "typical_days": list(user_events["day_of_week"].mode().values),
        "typical_ips": list(user_events["source_ip"].value_counts().head(10).index),
        "typical_locations": list(
            user_events["location"].apply(
                lambda x: x.get("country") if isinstance(x, dict) else None
            ).dropna().value_counts().head(5).index
        ),
        "typical_apps": list(user_events["app"].value_counts().head(10).index),
        "typical_devices": list(user_events["device"].value_counts().head(5).index),
        "avg_daily_logins": float(
            user_events.groupby(user_events["timestamp"].dt.date).size().mean()
        ),
        "std_daily_logins": float(
            user_events.groupby(user_events["timestamp"].dt.date).size().std()
        ),
        "failure_rate": float(
            (user_events["result"] == "failure").mean()
        )
    }

    return baseline

def detect_behavioral_anomalies(event, baseline):
    """Compare a new authentication event against user baseline."""
    anomalies = []
    event_time = pd.Timestamp(event["timestamp"])

    # Off-hours login detection
    hour = event_time.hour
    if baseline["typical_hours"]["std"] > 0:
        z_score = abs(hour - baseline["typical_hours"]["mean"]) / baseline["typical_hours"]["std"]
        if z_score > 2.5:
            anomalies.append({
                "type": "OFF_HOURS_LOGIN",
                "severity": "MEDIUM",
                "detail": f"Login at {hour}:00 (baseline: {baseline['typical_hours']['start']}:00-{baseline['typical_hours']['end']}:00)",
                "z_score": round(z_score, 2)
            })

    # New source IP
    if event["source_ip"] not in baseline["typical_ips"]:
        anomalies.append({
            "type": "NEW_SOURCE_IP",
            "severity": "MEDIUM",
            "detail": f"Login from unknown IP: {event['source_ip']}"
        })

    # New country
    if event.get("location") and isinstance(event["location"], dict):
        country = event["location"].get("country")
        if country and country not in baseline["typical_locations"]:
            anomalies.append({
                "type": "NEW_COUNTRY",
                "severity": "HIGH",
                "detail": f"Login from new country: {country}"
            })

    # New application
    if event.get("app") and event["app"] not in baseline["typical_apps"]:
        anomalies.append({
            "type": "NEW_APPLICATION",
            "severity": "LOW",
            "detail": f"Access to new application: {event['app']}"
        })

    # New device
    if event.get("device") and event["device"] not in baseline["typical_devices"]:
        anomalies.append({
            "type": "NEW_DEVICE",
            "severity": "MEDIUM",
            "detail": f"Login from new device: {event['device']}"
        })

    # Weekend login for weekday-only users
    if event_time.dayofweek >= 5 and 5 not in baseline["typical_days"] and 6 not in baseline["typical_days"]:
        anomalies.append({
            "type": "WEEKEND_LOGIN",
            "severity": "LOW",
            "detail": f"Weekend login detected (typical days: {baseline['typical_days']})"
        })

    return anomalies

def isolation_forest_anomaly_detection(df):
    """Use Isolation Forest for multivariate anomaly detection."""
    # Feature engineering
    features_df = df.copy()
    features_df["timestamp"] = pd.to_datetime(features_df["timestamp"])
    features_df["hour"] = features_df["timestamp"].dt.hour
    features_df["day_of_week"] = features_df["timestamp"].dt.dayofweek
    features_df["is_failure"] = (features_df["result"] == "failure").astype(int)

    # Encode categorical features
    features_df["ip_frequency"] = features_df.groupby("source_ip")["source_ip"].transform("count")
    features_df["user_frequency"] = features_df.groupby("user")["user"].transform("count")

    feature_columns = ["hour", "day_of_week", "is_failure", "ip_frequency", "user_frequency"]
    X = features_df[feature_columns].fillna(0)

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=200,
        contamination=0.01,  # Expect 1% anomaly rate
        random_state=42,
        n_jobs=-1
    )
    features_df["anomaly_score"] = model.fit_predict(X)
    features_df["anomaly_probability"] = model.score_samples(X)

    # Extract anomalies (labeled as -1)
    anomalies = features_df[features_df["anomaly_score"] == -1]

    return anomalies.sort_values("anomaly_probability")
```

## Step 6: Correlate and Score Authentication Anomalies

```python
def calculate_auth_risk_score(user, alerts, baseline):
    """
    Calculate composite risk score for authentication events.
    Combines multiple anomaly signals with weighted scoring.
    """
    score = 0
    risk_factors = []

    weights = {
        "IMPOSSIBLE_TRAVEL": 40,
        "PASSWORD_SPRAY": 35,
        "BRUTE_FORCE": 30,
        "CREDENTIAL_STUFFING": 35,
        "NEW_COUNTRY": 25,
        "OFF_HOURS_LOGIN": 15,
        "NEW_SOURCE_IP": 10,
        "NEW_DEVICE": 10,
        "NEW_APPLICATION": 5,
        "WEEKEND_LOGIN": 5,
        "MFA_BYPASS": 45,
        "LEGACY_PROTOCOL": 20
    }

    for alert in alerts:
        alert_type = alert.get("type") or alert.get("alert_type")
        weight = weights.get(alert_type, 10)

        # Adjust weight based on severity
        severity_multiplier = {
            "CRITICAL": 2.0,
            "HIGH": 1.5,
            "MEDIUM": 1.0,
            "LOW": 0.5
        }
        severity = alert.get("severity", "MEDIUM")
        adjusted_weight = weight * severity_multiplier.get(severity, 1.0)

        score += adjusted_weight
        risk_factors.append({
            "factor": alert_type,
            "weight": adjusted_weight,
            "detail": alert.get("detail", alert.get("details", ""))
        })

    # Normalize score to 0-100
    normalized_score = min(100, score)

    # Determine risk level
    if normalized_score >= 80:
        risk_level = "CRITICAL"
        recommended_action = "Immediate account suspension and investigation"
    elif normalized_score >= 60:
        risk_level = "HIGH"
        recommended_action = "Force MFA re-enrollment and notify SOC"
    elif normalized_score >= 40:
        risk_level = "MEDIUM"
        recommended_action = "Require step-up authentication"
    elif normalized_score >= 20:
        risk_level = "LOW"
        recommended_action = "Monitor and log for trend analysis"
    else:
        risk_level = "INFORMATIONAL"
        recommended_action = "No action required"

    return {
        "user": user,
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "recommended_action": recommended_action,
        "risk_factors": sorted(risk_factors, key=lambda x: x["weight"], reverse=True),
        "timestamp": datetime.utcnow().isoformat()
    }
```
