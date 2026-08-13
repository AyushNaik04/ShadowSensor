import sqlite3, json

DB = r"C:\ShadowSensor\data\shadowsensor.db"
conn = sqlite3.connect(DB)

# Step 1: rule_hits for PS_DOWNLOAD_CRADLE_001 today
print("=== PS_DOWNLOAD_CRADLE_001 rule_hits today ===")
hits = conn.execute(
    "SELECT id, timestamp FROM rule_hits "
    "WHERE rule_id = 'PS_DOWNLOAD_CRADLE_001' "
    "AND timestamp >= '2026-08-12 08:10:00' "
    "ORDER BY timestamp"
).fetchall()
print(f"{len(hits)} hit(s)")
for h in hits:
    print(f"  id={h[0]}  ts={h[1]}")

# Step 2: ALL EID-1 powershell.exe events from 08:10 to 08:16 today
# This covers the entire FP test window with generous padding
print("\n=== All EID-1 powershell.exe events 08:10–08:16 UTC ===")
rows = conn.execute(
    "SELECT timestamp, raw_json FROM events "
    "WHERE event_type_id = 1 "
    "AND timestamp BETWEEN '2026-08-12 08:10:00' AND '2026-08-12 08:16:00' "
    "ORDER BY timestamp"
).fetchall()
print(f"{len(rows)} EID-1 event(s) in window")
for ts, raw in rows:
    d = json.loads(raw)
    image   = d.get("image", d.get("Image", "N/A"))
    cmdline = d.get("command_line", d.get("CommandLine", "N/A"))
    parent  = d.get("parent_image", d.get("ParentImage", "N/A"))
    if "powershell" in image.lower():
        print(f"\n  [PS] event_ts : {ts}")
        print(f"       image    : {image}")
        print(f"       cmdline  : {cmdline}")
        print(f"       parent   : {parent}")

# Step 3: Any EID-1 event with WebClient or New-Object in raw_json today
print("\n=== EID-1 events with 'WebClient' or 'Net.WebClient' in raw_json (08:10–08:16) ===")
rows2 = conn.execute(
    "SELECT timestamp, raw_json FROM events "
    "WHERE event_type_id = 1 "
    "AND timestamp BETWEEN '2026-08-12 08:10:00' AND '2026-08-12 08:16:00' "
    "AND (raw_json LIKE '%WebClient%' OR raw_json LIKE '%New-Object%') "
    "ORDER BY timestamp"
).fetchall()
print(f"{len(rows2)} matching event(s)")
for ts, raw in rows2:
    d = json.loads(raw)
    print(f"\n  event_ts : {ts}")
    print(f"  image    : {d.get('image', d.get('Image', 'N/A'))}")
    print(f"  cmdline  : {d.get('command_line', d.get('CommandLine', 'N/A'))}")
    print(f"  parent   : {d.get('parent_image', d.get('ParentImage', 'N/A'))}")

conn.close()

