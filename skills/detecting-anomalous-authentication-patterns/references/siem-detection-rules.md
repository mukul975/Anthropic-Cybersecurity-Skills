# SIEM Detection Rules (Splunk SPL)

Deployable Splunk SPL queries for the common authentication attack patterns described in Step 5 of `SKILL.md`.

```yaml
# Splunk SPL queries for authentication anomaly detection

# 1. Brute Force Detection
# name: Authentication Brute Force - Multiple Failed Logins
# severity: high
brute_force_spl: |
  index=auth sourcetype IN ("azure:aad:signin", "okta:im:log", "WinEventLog:Security")
  (result="failure" OR EventCode=4625)
  | bin _time span=10m
  | stats count as failed_attempts dc(src_ip) as unique_ips
    values(src_ip) as source_ips
    latest(_time) as last_attempt
    by user _time
  | where failed_attempts >= 10
  | eval alert_type=if(unique_ips > 3, "Distributed Brute Force", "Standard Brute Force")

# 2. Password Spray Detection
# name: Password Spray Attack - Multiple Users Same Source
# severity: critical
password_spray_spl: |
  index=auth sourcetype IN ("azure:aad:signin", "okta:im:log")
  result="failure"
  | bin _time span=30m
  | stats dc(user) as targeted_users count as total_attempts
    values(user) as users_targeted
    by src_ip _time
  | where targeted_users >= 10
  | eval attempts_per_user = round(total_attempts / targeted_users, 1)
  | where attempts_per_user <= 3
  | eval severity=if(targeted_users > 50, "CRITICAL", "HIGH")

# 3. Impossible Travel Detection
# name: Impossible Travel - Geographically Inconsistent Logins
# severity: high
impossible_travel_spl: |
  index=auth result="success"
  | iplocation src_ip
  | sort user _time
  | streamstats current=f last(lat) as prev_lat last(lon) as prev_lon
    last(_time) as prev_time last(City) as prev_city last(Country) as prev_country
    by user
  | where isnotnull(prev_lat) AND isnotnull(lat)
  | eval distance_km = 6371 * 2 * asin(sqrt(
      pow(sin((lat - prev_lat) * pi() / 360), 2) +
      cos(prev_lat * pi() / 180) * cos(lat * pi() / 180) *
      pow(sin((lon - prev_lon) * pi() / 360), 2)))
  | eval time_hours = (_time - prev_time) / 3600
  | eval required_speed = distance_km / time_hours
  | where required_speed > 900 AND distance_km > 100

# 4. Credential Stuffing Detection
# name: Credential Stuffing - High Volume Failed Logins with Some Successes
# severity: critical
credential_stuffing_spl: |
  index=auth
  | bin _time span=1h
  | stats count(eval(result="failure")) as failures
    count(eval(result="success")) as successes
    dc(user) as unique_users
    dc(src_ip) as unique_ips
    by src_ip _time
  | where failures > 100 AND successes > 0 AND unique_users > 20
  | eval success_rate = round(successes / (failures + successes) * 100, 2)
  | where success_rate < 5
```
