import uuid
import sqlite3
import nmap
import pyfiglet
from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

print(pyfiglet.figlet_format("NetSecure Lab"))

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target_ip: str
    port_range: str


def get_db_connection():
    conn = sqlite3.connect("scans.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Added scan_id column for absolute session isolation
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            target_ip TEXT,
            port INTEGER,
            state TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


init_db()


def nmap_scan(target_ip: str, port_range: str):
    scanner = nmap.PortScanner()

    try:
        scanner.scan(target_ip, port_range, arguments="-sT -sV -Pn")
    except Exception as e:
        print(f"[Nmap Execution Error]: {e}")
        raise RuntimeError(f"Nmap scanner failure: {str(e)}")

    conn = get_db_connection()
    cursor = conn.cursor()

    found_ports = []
    # Unique identifier for this scan session
    session_id = str(uuid.uuid4())[:8]

    try:
        if target_ip in scanner.all_hosts():
            host_data = scanner[target_ip]

            for proto in host_data.all_protocols():
                protocol_ports = host_data[proto]

                for port, info in protocol_ports.items():
                    state = info.get("state", "unknown")
                    service = info.get("name", "unknown")
                    product = info.get("product", "N/A")
                    version = info.get("version", "N/A")

                    if state.lower() == "open":
                        cursor.execute("""
                            INSERT INTO scan_results (scan_id, target_ip, port, state, service, product, version)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (session_id, target_ip, port, state, service, product, version))

                        found_ports.append({
                            "scan_id": session_id,
                            "port": port,
                            "state": state,
                            "service": service,
                            "product": product,
                            "version": version
                        })

            conn.commit()
    finally:
        conn.close()

    return found_ports


@app.get("/")
def home():
    return {"status": "Active", "system": "NetSecure Lab Core Engine"}


@app.get("/api/results")
def get_results():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_results 
            WHERE scan_id = (SELECT scan_id FROM scan_results ORDER BY id DESC LIMIT 1)
            ORDER BY id DESC""")
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]
    except Exception as e:
        print(f"[Database Read Error]: {e}")
        raise HTTPException(status_code=500, detail="Database read error")


@app.post("/api/scan")
async def trigger_scan(request: ScanRequest):
    try:
        results = await run_in_threadpool(
            nmap_scan, request.target_ip, request.port_range
        )

        if not results:
            return {
                "status": "warning",
                "message": f"Host {request.target_ip} reached, but no open TCP ports were found in range [{request.port_range}].",
                "results": []
            }

        return {
            "status": "success",
            "message": f"Scan successfully executed. Discovered {len(results)} open port(s).",
            "results": results
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Scan execution failed: {str(e)}"
        )


if __name__ == "__main__":
    pass
