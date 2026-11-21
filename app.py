import ipaddress
import logging
import re
from threading import Lock

from flask import Flask, jsonify, render_template, request

from database import (
    acknowledge_alerts,
    delete_device,
    get_settings,
    initialize,
    list_alerts,
    list_devices,
    list_history,
    set_trusted,
    update_settings,
)
from scanner import NetworkScanner


logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
scanner = NetworkScanner()
scanner_start_lock = Lock()

MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def ensure_scanner_started() -> None:
    with scanner_start_lock:
        if not scanner.thread.is_alive():
            scanner.start()


def valid_mac(mac: str) -> bool:
    return bool(MAC_PATTERN.fullmatch(mac.strip()))


@app.get("/")
def index():
    ensure_scanner_started()
    return render_template("index.html")


@app.get("/api/overview")
def overview():
    devices = list_devices()
    alerts = list_alerts()
    settings = get_settings()
    online = [device for device in devices if device["status"] == "online"]
    trusted = [device for device in devices if device["is_trusted"]]
    return jsonify(
        {
            "total_devices": len(devices),
            "online_devices": len(online),
            "trusted_devices": len(trusted),
            "unknown_devices": len([device for device in online if not device["is_trusted"]]),
            "network_status": "Online" if online else "Local network active",
            "subnet": settings["subnet"],
            "scan_interval": settings["scan_interval"],
            "scanner_active": scanner.running,
            "alert_count": len(alerts),
            "recent_alerts": alerts[:5],
        }
    )


@app.get("/api/devices")
def devices():
    return jsonify(list_devices())


@app.post("/api/devices/trust")
def trust_device():
    payload = request.get_json(silent=True) or {}
    mac = str(payload.get("mac", "")).strip().lower()
    if not valid_mac(mac):
        return jsonify({"error": "A valid MAC address is required"}), 400
    device = next((item for item in list_devices() if item["mac"] == mac), None)
    trusted = payload.get("trusted")
    if trusted is None:
        trusted = not bool(device and device["is_trusted"])
    result = set_trusted(mac, bool(trusted), str(payload.get("ip", device["ip"] if device else "Unknown")))
    return jsonify(result)


@app.delete("/api/devices/<path:mac>")
def remove_device(mac: str):
    if not valid_mac(mac):
        return jsonify({"error": "A valid MAC address is required"}), 400
    if not delete_device(mac):
        return jsonify({"error": "Device not found"}), 404
    return jsonify({"success": True})


@app.get("/api/alerts")
def alerts():
    return jsonify(list_alerts())


@app.post("/api/alerts/clear")
def clear_alerts():
    acknowledge_alerts()
    return jsonify({"success": True})


@app.get("/api/history")
def history():
    return jsonify(list_history())


@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "GET":
        return jsonify(get_settings())
    payload = request.get_json(silent=True) or {}
    try:
        subnet = str(payload.get("subnet", get_settings()["subnet"])).strip()
        ipaddress.ip_network(subnet, strict=False)
        result = update_settings(payload)
    except (ValueError, TypeError) as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(result)


initialize()


# if __name__ == "__main__":
#     ensure_scanner_started()
#     app.run(host="0.0.0.0", port=5000, debug=False)
