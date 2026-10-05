# NetSecure Lab - Nmap Recon Dashboard

A full-stack network reconnaissance web application that integrates **FastAPI**, **python-nmap**, and an interactive dashboard UI to execute port scans, detect services/versions, and display audit telemetry stored in SQLite.

## Features

- **Real-Time Port Scanning:** Asynchronous background scanning powered by `python-nmap` and FastAPI thread pools (`-sT -sV -Pn`).
- **Session Isolation (`scan_id`):** UUID-tagged scan sessions ensure accurate KPI aggregation and eliminate historical metric contamination.
- **Dynamic Threat Assessment:** Automatic threat status calculation (Low/Medium/High) based on active target attack surface.
- **Persistent Telemetry Logging:** SQLite backend storing historical scan telemetry with instant refresh capabilities.

## Tech Stack

- **Backend:** Python 3, FastAPI, SQLite3, `python-nmap`
- **Frontend:** HTML5, CSS3, JavaScript (Fetch API, DOM manipulation)
- **Engine:** Nmap Security Scanner

## Getting Started

### Prerequisites

- Python 3.10+
- Nmap installed on the host machine (`sudo apt install nmap` on Kali/Linux)

### Installation & Execution

1. Clone the repository:
   ```bash
   git clone [https://github.com/Isholexy/netsecure-recon-dashboard.git](https://github.com/Isholexy/netsecure-recon-dashboard.git)
   cd netsecure-recon-dashboard
   ```

### Activate your virtual environment and install dependencies:

source .venv/bin/activate
pip install fastapi uvicorn python-nmap pyfiglet

### Start the FastAPI backend server:

uvicorn main:app --reload
