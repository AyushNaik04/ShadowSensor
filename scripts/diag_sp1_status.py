import sqlite3

DB = r"C:\ShadowSensor\data\shadowsensor.db"
conn = sqlite3.connect(DB)

# All rule_hits for Subphase 1 rules since today's sim start
PS_RULES = [
    "PS_ENCODED_CMD_001",
    "PS_DOWNLOAD_CRADLE_001",
    "PS_AMSI_BYPASS_001",
    "PS_HIDDEN_WINDOW_001",
    "PS_EXECUTION_POLICY_BYPASS_001",
    "PS_INVOKE_EXPRESSION_001",
    "PS_VERSION_DOWNGRADE_001",
    "PS_REFLECTIVE_ASSEMBLY_001",
    "PS_CREDENTIAL_ACCESS_001",
    "PS_CONSTRAINED_LANG_BYPASS_001",
    "PS_WMI_EXEC_001",
]

print("=== Subphase 1 rule_hits today (since 08:00 UTC) ===")
print(f"{'RULE':<40} {'HITS':>5}")
print("-" * 47)
total = 0
for rule in PS_RULES:
    n = conn.execute(
        "SELECT COUNT(*) FROM rule_hits WHERE rule_id=? AND timestamp >= '2026-08-12 08:00:00'",
        (rule,)
    ).fetchone()[0]
    total += n
    print(f"{rule:<40} {n:>5}")

print("-" * 47)
print(f"{'TOTAL':<40} {total:>5}")

# Most recent hit timestamp to know how far the pipeline has caught up
latest = conn.execute(
    "SELECT rule_id, timestamp FROM rule_hits "
    "WHERE timestamp >= '2026-08-12 08:00:00' "
    "ORDER BY timestamp DESC LIMIT 1"
).fetchone()
if latest:
    print(f"\nMost recent hit: {latest[0]} at {latest[1]}")

conn.close()
