import sqlite3, json
conn = sqlite3.connect(r'C:\ShadowSensor\data\shadowsensor.db')
conn.row_factory = sqlite3.Row
rows = conn.execute('''
    SELECT id, timestamp, raw_json FROM events
    WHERE event_type_id = 10
      AND raw_json LIKE '%powershell%notepad%'
      AND timestamp BETWEEN '2026-08-11 06:38:30' AND '2026-08-11 06:40:00'
    ORDER BY id ASC
''').fetchall()
conn.close()
print(f'Rows found: {len(rows)}')
for r in rows:
    d = json.loads(r['raw_json'])
    print(f"id={r['id']} ts={r['timestamp']} source={d.get('source_image')} target={d.get('target_image')} granted_access={d.get('granted_access')}")
    print(f"  call_trace={d.get('call_trace')!r}")
