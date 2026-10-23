
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
from collections import Counter
import csv
import os
from pathlib import Path


# Configure CSV paths using environment variables.
# Leave them empty to use the existing demo data.
FLOW_CSV_PATH = os.getenv("SENTINEL_FLOW_CSV", "").strip()
PREDICTION_CSV_PATH = os.getenv("SENTINEL_PREDICTION_CSV", "").strip()
ALERT_CSV_PATH = os.getenv("SENTINEL_ALERT_CSV", "").strip()


app = FastAPI(
    title="SENTINEL Network Defense API",
    description="Backend API for the SENTINEL NIDS dashboard",
    version="0.2.0",
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


# -------------------- CSV HELPERS --------------------

def read_csv_file(configured_path):
    """Return CSV rows, None if not configured, or raise on file errors."""
    if not configured_path:
        return None

    csv_path = Path(configured_path)

    if not csv_path.is_file():
        raise FileNotFoundError(
            f"Configured CSV file was not found: {csv_path}"
        )

    with csv_path.open("r", newline="", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


def read_flow_csv():
    return read_csv_file(FLOW_CSV_PATH)


def read_prediction_csv():
    return read_csv_file(PREDICTION_CSV_PATH)


def read_alert_csv():
    return read_csv_file(ALERT_CSV_PATH)


def csv_error_response(error):
    """Create a consistent HTTP error for unavailable configured files."""
    raise HTTPException(
        status_code=503,
        detail={
            "mode": "unavailable",
            "message": str(error),
        },
    )


def protocol_name(value):
    """Convert common IP protocol numbers to readable names."""
    value = str(value or "").strip()

    return {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
    }.get(value, f"Protocol {value}" if value else "Unknown")


def format_flow_rows(rows, predictions=None):
    """Format raw CICFlowMeter rows for the frontend."""
    predictions = predictions or []

    # Match prediction records to flow identifiers.
    prediction_map = {
        str(row.get("flow_id", "")): row
        for row in predictions
        if row.get("flow_id")
    }

    formatted = []

    for index, row in enumerate(rows, start=1):
        src_ip = row.get("src_ip") or row.get("source_ip") or "Unknown"
        dst_ip = row.get("dst_ip") or row.get("destination_ip") or "Unknown"
        src_port = str(row.get("src_port") or "")
        dst_port = row.get("dst_port") or row.get("destination_port") or "-"

        flow_id = (
            f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            if src_port
            else ""
        )

        prediction = prediction_map.get(flow_id, {})

        prediction_type = prediction.get("prediction")
        if prediction_type:
            prediction_type = (
                "Potential threat"
                if prediction_type.upper() == "ATTACK"
                else "Benign"
                if prediction_type.upper() == "BENIGN"
                else prediction_type
            )
        else:
            prediction_type = "Unclassified"

        formatted.append({
            "id": flow_id or f"FL-{index:04d}",
            "src": src_ip,
            "dst": dst_ip,
            "port": dst_port,
            "protocol": protocol_name(row.get("protocol")),
            "type": prediction_type,
            "time": row.get("timestamp") or row.get("time") or "-",
            "attack_probability": prediction.get("attack_probability"),
            "severity": prediction.get("severity", "NONE"),
        })

    return formatted


def format_prediction_rows(rows):
    """Format ML predictions for the frontend."""
    formatted = []

    for index, row in enumerate(rows, start=1):
        prediction = str(row.get("prediction", "UNKNOWN")).upper()

        formatted.append({
            "id": row.get("flow_id") or f"FL-{index:04d}",
            "src": row.get("src_ip") or "Unknown",
            "dst": row.get("dst_ip") or "Unknown",
            "port": row.get("dst_port") or "-",
            "protocol": protocol_name(row.get("protocol")),
            "type": (
                "Potential threat" if prediction == "ATTACK"
                else "Benign" if prediction == "BENIGN"
                else prediction
            ),
            "prediction": prediction,
            "attack_probability": safe_float(row.get("attack_probability")),
            "threshold": safe_float(row.get("threshold")),
            "severity": row.get("severity") or "NONE",
            "time": row.get("timestamp_utc") or "-",
            "alert": str(row.get("alert", "")).lower() == "true",
        })

    return formatted


def format_alert_rows(rows):
    """Format the existing alert CSV for the frontend."""
    formatted = []

    for index, row in enumerate(rows, start=1):
        flow_id = row.get("flow_id") or f"ALT-{index:03d}"

        # The alert CSV contains no IP/port columns, so recover them
        # from the matching prediction record when possible.
        formatted.append({
            "id": flow_id,
            "src": row.get("src_ip") or "Unknown",
            "dst": row.get("dst_ip") or "Unknown",
            "port": row.get("dst_port") or "-",
            "protocol": protocol_name(row.get("protocol")),
            "type": "Potential threat",
            "time": row.get("timestamp_utc") or "-",
            "severity": row.get("severity") or "UNKNOWN",
            "attack_probability": safe_float(row.get("attack_probability")),
        })

    return formatted


def safe_float(value):
    """Convert a CSV value to a number, or return None."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def get_demo_flows():
    return [
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
    ]


def get_demo_alerts():
    return [
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
    ]


# -------------------- API ROUTES --------------------

@app.get("/")
def root():
    return {
        "name": "SENTINEL Network Defense API",
        "status": "running",
    }


@app.get("/api/health")
def health():
    configured_paths = [
        FLOW_CSV_PATH,
        PREDICTION_CSV_PATH,
        ALERT_CSV_PATH,
    ]

    return {
        "status": "healthy",
        "service": "sentinel-api",
        "detection_pipeline": (
            "data_sources_configured"
            if any(configured_paths)
            else "not_connected"
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/overview")
def overview():
    try:
        flows = read_flow_csv()
        predictions = read_prediction_csv()
        alerts = read_alert_csv()
    except (OSError, csv.Error) as error:
        csv_error_response(error)

    # Use real predictions when configured.
    if predictions is not None:
        benign_count = sum(
            str(row.get("prediction", "")).upper() == "BENIGN"
            for row in predictions
        )
        attack_count = sum(
            str(row.get("prediction", "")).upper() == "ATTACK"
            for row in predictions
        )

        return {
            "mode": "live",
            "captured_flows": len(flows) if flows is not None else len(predictions),
            "benign_flows": benign_count,
            "potential_threats": attack_count,
            "recorded_alerts": len(alerts) if alerts is not None else sum(
                str(row.get("alert", "")).lower() == "true"
                for row in predictions
            ),
        }

    if flows is not None:
        return {
            "mode": "live",
            "captured_flows": len(flows),
            "benign_flows": 0,
            "potential_threats": 0,
            "recorded_alerts": len(alerts) if alerts is not None else 0,
        }

    if alerts is not None:
        return {
            "mode": "live",
            "captured_flows": 0,
            "benign_flows": 0,
            "potential_threats": len(alerts),
            "recorded_alerts": len(alerts),
        }

    return {
        "mode": "demo",
        "captured_flows": 24891,
        "benign_flows": 22416,
        "potential_threats": 2475,
        "recorded_alerts": 128,
    }


@app.get("/api/flows")
def get_flows():
    try:
        rows = read_flow_csv()
        predictions = read_prediction_csv()
    except (OSError, csv.Error) as error:
        csv_error_response(error)

    if rows is not None:
        return {
            "mode": "live",
            "flows": format_flow_rows(rows, predictions),
        }

    if predictions is not None:
        return {
            "mode": "live",
            "flows": format_prediction_rows(predictions),
        }

    return {
        "mode": "demo",
        "flows": get_demo_flows(),
    }


@app.get("/api/predictions")
def get_predictions():
    try:
        rows = read_prediction_csv()
    except (OSError, csv.Error) as error:
        csv_error_response(error)

    if rows is not None:
        return {
            "mode": "live",
            "predictions": format_prediction_rows(rows),
        }

    return {
        "mode": "demo",
        "predictions": format_prediction_rows([
            {
                "flow_id": "DEMO-001",
                "prediction": "BENIGN",
                "attack_probability": "0.04",
                "threshold": "0.256",
                "alert": "False",
                "severity": "NONE",
                "src_ip": "192.168.1.14",
                "dst_ip": "185.199.110.153",
                "dst_port": "443",
                "protocol": "6",
                "timestamp_utc": "14:32:18",
            },
            {
                "flow_id": "DEMO-002",
                "prediction": "ATTACK",
                "attack_probability": "0.91",
                "threshold": "0.256",
                "alert": "True",
                "severity": "HIGH",
                "src_ip": "192.168.1.22",
                "dst_ip": "45.33.32.156",
                "dst_port": "22",
                "protocol": "6",
                "timestamp_utc": "14:31:52",
            },
        ]),
    }


@app.get("/api/alerts")
def get_alerts():
    try:
        rows = read_alert_csv()
        predictions = read_prediction_csv()
    except (OSError, csv.Error) as error:
        csv_error_response(error)

    if rows is not None:
        # Enrich alert records with IP addresses and protocol from predictions.
        prediction_map = {
            str(row.get("flow_id", "")): row
            for row in (predictions or [])
            if row.get("flow_id")
        }

        enriched_rows = []
        for row in rows:
            match = prediction_map.get(str(row.get("flow_id", "")), {})
            enriched_rows.append({**match, **row})

        return {
            "mode": "live",
            "alerts": format_alert_rows(enriched_rows),
        }

    if predictions is not None:
        alert_predictions = [
            row for row in predictions
            if str(row.get("alert", "")).lower() == "true"
        ]
        return {
            "mode": "live",
            "alerts": format_alert_rows(alert_predictions),
        }

    return {
        "mode": "demo",
        "alerts": get_demo_alerts(),
    }


@app.get("/api/analytics")
def get_analytics():
    try:
        flows = read_flow_csv()
        predictions = read_prediction_csv()
    except (OSError, csv.Error) as error:
        csv_error_response(error)

    if flows is not None or predictions is not None:
        source_rows = flows if flows is not None else predictions
        protocol_counts = Counter(
            protocol_name(row.get("protocol"))
            for row in source_rows
        )

        traffic = [{
            "time": datetime.now(timezone.utc).strftime("%H:%M"),
            "flows": len(source_rows),
            "threats": sum(
                str(row.get("prediction", "")).upper() == "ATTACK"
                or str(row.get("alert", "")).lower() == "true"
                for row in source_rows
            ),
        }]

        total = sum(protocol_counts.values()) or 1
        protocols = [
            {
                "name": name,
                "value": round(count * 100 / total, 2),
            }
            for name, count in protocol_counts.items()
        ]

        return {
            "mode": "live",
            "traffic": traffic,
            "protocols": protocols,
        }

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
    components = [
        {
            "name": "Network Capture",
            "status": "not_connected",
        },
        {
            "name": "CICFlowMeter",
            "status": "not_connected",
        },
        {
            "name": "ML Detection Model",
            "status": "not_connected",
        },
        {
            "name": "Alert Engine",
            "status": "not_connected",
        },
    ]

    configured = [
        ("CICFlowMeter", FLOW_CSV_PATH),
        ("ML Detection Model", PREDICTION_CSV_PATH),
        ("Alert Engine", ALERT_CSV_PATH),
    ]

    for component_name, configured_path in configured:
        component = next(
            item for item in components
            if item["name"] == component_name
        )

        if configured_path:
            component["status"] = (
                "connected"
                if Path(configured_path).is_file()
                else "unavailable"
            )

    return {
        "mode": (
            "live"
            if any([FLOW_CSV_PATH, PREDICTION_CSV_PATH, ALERT_CSV_PATH])
            else "demo"
        ),
        "components": components,
    }
