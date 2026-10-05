import sqlite3

conn = sqlite3.connect("scans.db")
cursor = conn.cursor()

cursor.execute(
    "SELECT id, target_ip, port, service, product, version, timestamp FROM scan_results")
rows = cursor.fetchall()

print("\n--- HISTORICAL SCAN DATABASE LOG ---")
for row in rows:
    print(
        f"ID #{row[0]} | Host: {row[1]} | Port {row[2]} ({row[3]}) | {row[4]} {row[5]} | Date: {row[6]}")

conn.close()
