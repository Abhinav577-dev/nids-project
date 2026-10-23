from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
import csv
import os
from pathlib import Path

# Optional path to a real flow CSV file.
# Leave unset while running in demo mode on Windows.
FLOW_CSV_PATH = os.getenv("SENTINEL_FLOW_CSV", "")


def read_flow_csv():
    """Read flow records from a configured CSV file."""
    if not FLOW_CSV_PATH:
        return None

    csv_path = Path(FLOW_CSV_PATH)

    if not csv_path.is_file():
        return None

    with csv_path.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        return list(reader)

def format_flow_rows(rows):
    """Convert CSV rows into the format expected by the frontend."""
    formatted = []

    for index, row in enumerate(rows, start=1):
        # Normalize CSV column names for flexible matching.
        normalized = {
            str(key).strip().lower().replace(" ", "_"): value
            for key, value in row.items()
            if key is not None
        }

        src = normalized.get("src_ip") or normalized.get("source_ip") or "Unknown"
        dst = normalized.get("dst_ip") or normalized.get("destination_ip") or "Unknown"
        protocol = normalized.get("protocol") or "Unknown"

        formatted.append({
            "id": normalized.get("id") or f"FL-{index:04d}",
            "src": src,
            "dst": dst,
            "port": normalized.get("dst_port") or normalized.get("destination_port") or "-",
            "protocol": protocol,
            "type": normalized.get("type") or normalized.get("prediction") or "Unknown",
            "time": normalized.get("time") or normalized.get("timestamp") or "-",
        })

    return formatted

app = FastAPI(
    title="SENTINEL Network Defense API",
    description="Backend API for the SENTINEL NIDS dashboard",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "name": "SENTINEL Network Defense API",
        "status": "running",
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "sentinel-api",
        "detection_pipeline": "not_connected",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/overview")
def overview():
    return {
        "mode": "demo",
        "captured_flows": 24891,
        "benign_flows": 22416,
        "potential_threats": 2475,
        "recorded_alerts": 128,
    }


@app.get("/api/flows")
def get_flows():
    rows = read_flow_csv()

    if rows is not None:
        return {
            "mode": "live",
            "flows": format_flow_rows(rows),
        }

    return {
        "mode": "demo",
        "flows": [
            {
                "id": "FL-1082",
                "src": "192.168.1.14",
                "dst": "185.199.110.153",
                "port": 443,
                "protocol": "TCP",
                "type": "Benign",
                "time": "14:32:18",
            },
            {
                "id": "FL-1081",
                "src": "192.168.1.22",
                "dst": "45.33.32.156",
                "port": 22,
                "protocol": "TCP",
                "type": "Potential threat",
                "time": "14:31:52",
            },
            {
                "id": "FL-1080",
                "src": "192.168.1.14",
                "dst": "142.250.183.14",
                "port": 443,
                "protocol": "TCP",
                "type": "Benign",
                "time": "14:30:41",
            },
            {
                "id": "FL-1079",
                "src": "192.168.1.19",
                "dst": "103.21.244.0",
                "port": 80,
                "protocol": "TCP",
                "type": "Potential threat",
                "time": "14:29:06",
            },
            {
                "id": "FL-1078",
                "src": "192.168.1.22",
                "dst": "8.8.8.8",
                "port": 53,
                "protocol": "UDP",
                "type": "Benign",
                "time": "14:28:33",
            },
        ],
    }

@app.get("/api/alerts")
def get_alerts():
    return {
        "mode": "demo",
        "alerts": [
            {
                "id": "ALT-001",
                "src": "192.168.1.22",
                "dst": "45.33.32.156",
                "port": 22,
                "protocol": "TCP",
                "type": "Potential threat",
                "time": "14:31:52",
                "severity": "High",
            },
            {
                "id": "ALT-002",
                "src": "192.168.1.19",
                "dst": "103.21.244.0",
                "port": 80,
                "protocol": "TCP",
                "type": "Potential threat",
                "time": "14:29:06",
                "severity": "Medium",
            },
        ],
    }


@app.get("/api/analytics")
def get_analytics():
    return {
        "mode": "demo",
        "traffic": [
            {"time": "09:00", "flows": 120, "threats": 12},
            {"time": "10:00", "flows": 185, "threats": 18},
            {"time": "11:00", "flows": 240, "threats": 25},
            {"time": "12:00", "flows": 310, "threats": 31},
            {"time": "13:00", "flows": 290, "threats": 19},
            {"time": "14:00", "flows": 460, "threats": 48},
        ],
        "protocols": [
            {"name": "TCP", "value": 58},
            {"name": "UDP", "value": 27},
            {"name": "Other", "value": 15},
        ],
    }

@app.get("/api/pipeline")
def get_pipeline():
    return {
        "mode": "demo",
        "components": [
            {"name": "Network Capture", "status": "not_connected"},
            {"name": "CICFlowMeter", "status": "not_connected"},
            {"name": "ML Detection Model", "status": "not_connected"},
            {"name": "Alert Engine", "status": "not_connected"},
        ],
    }