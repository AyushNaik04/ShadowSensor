import sqlite3

DB = r"C:\ShadowSensor\data\shadowsensor.db"
conn = sqlite3.connect(DB)

print("=== Recent EID 1 (ProcessCreate) events — last 10 ===")
rows = conn.execute(
    "SELECT timestamp, image, raw_json FROM events WHERE event_type_id=1 ORDER BY timestamp DESC LIMIT 10"
).fetchall()
print(len(rows), "EID-1 events")
for ts, image, raw in rows:
    import json
    d = json.loads(raw)
    cmdline = d.get("command_line", d.get("CommandLine", "N/A"))
    parent = d.get("parent_image", d.get("ParentImage", "N/A"))
    print(f"  [{ts}] image={image}")
    print(f"         cmdline={cmdline}")
    print(f"         parent={parent}")
    print()

print()
print("=== EID 1 events with iwr or Invoke-WebRequest in raw_json (all time) ===")
rows2 = conn.execute(
    "SELECT timestamp, raw_json FROM events WHERE event_type_id=1 AND (raw_json LIKE '%iwr%' OR raw_json LIKE '%Invoke-WebRequest%') ORDER BY timestamp DESC LIMIT 10"
).fetchall()
print(len(rows2), "matching EID-1 events")
for ts, raw in rows2:
    import json
    d = json.loads(raw)
    cmdline = d.get("command_line", d.get("CommandLine", "N/A"))
    parent = d.get("parent_image", d.get("ParentImage", "N/A"))
    print(f"  [{ts}] cmdline={cmdline}")
    print(f"         parent={parent}")
    print()

conn.close()
