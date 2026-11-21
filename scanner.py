import logging
import os
import platform
import subprocess
import threading
from socket import gethostbyaddr, herror, gaierror

from database import (
    get_settings,
    mark_missing_offline,
    trusted_macs,
    upsert_scan_device,
)

logger = logging.getLogger(__name__)
DEFAULT_SUBNET = "192.168.1.0/24"
SCAN_EVERY = 5

try:
    from scapy.all import ARP, Ether, conf, srp
except ImportError:
    ARP = Ether = conf = srp = None

try:
    from plyer import notification
except ImportError:
    notification = None


class NetworkScanner:
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="netguard-scanner", daemon=True)
        self.running = False

    def start(self) -> None:
        if not self.thread.is_alive():
            if self.stop_event.is_set():
                self.stop_event = threading.Event()
                self.thread = threading.Thread(
                    target=self._run, name="netguard-scanner", daemon=True
                )
            self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.running = False

    @staticmethod
    def scan(network: str) -> list[tuple[str, str]]:
        if ARP is None or Ether is None or srp is None:
            raise RuntimeError("Scapy is not installed; install requirements.txt to enable scanning")
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        interface = None
        if platform.system() == "Windows":
            interface = conf.iface if conf is not None else None
        answered, _ = srp(packet, timeout=2, verbose=False, iface=interface)
        return [(received.psrc, received.hwsrc.lower()) for _, received in answered]

    @staticmethod
    def _notify(ip: str, mac: str) -> None:
        message = f"IP: {ip} | MAC: {mac}"
        logger.warning("Unknown device detected: %s", message)
        if notification is not None and platform.system() == "Windows":
            notification.notify(title="NetGuard: Rogue Device", message=message, timeout=10)
            return
        if platform.system() != "Windows":
            user = os.environ.get("SUDO_USER")
            command = ["notify-send", "-u", "critical", "NetGuard: Rogue Device", message]
            if user:
                try:
                    uid = subprocess.check_output(["id", "-u", user], text=True).strip()
                    command = [
                        "sudo", "-u", user,
                        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                        *command,
                    ]
                except (OSError, subprocess.SubprocessError) as error:
                    logger.warning("Unable to resolve desktop notification user: %s", error)
            try:
                subprocess.run(command, check=False)
            except OSError as error:
                logger.warning("Desktop notification unavailable: %s", error)

    @staticmethod
    def _hostname(ip: str) -> str:
        try:
            return gethostbyaddr(ip)[0]
        except (herror, gaierror, OSError):
            return "Unknown"

    def scan_once(self) -> None:
        settings = get_settings()
        trusted = trusted_macs()
        seen_macs: set[str] = set()
        for ip, mac in self.scan(settings["subnet"]):
            seen_macs.add(mac)
            is_new, device = upsert_scan_device(ip, mac, self._hostname(ip), mac in trusted)
            if is_new and not device["is_trusted"] and settings["desktop_notifications"]:
                self._notify(ip, mac)
        mark_missing_offline(seen_macs)

    def _run(self) -> None:
        if platform.system() == "Windows" and conf is not None:
            try:
                conf.iface = conf.route.route("0.0.0.0")[0]
            except (AttributeError, OSError, RuntimeError) as error:
                logger.warning("Unable to select the Windows network interface: %s", error)
        self.running = True
        while not self.stop_event.is_set():
            try:
                self.scan_once()
            except (RuntimeError, OSError, ValueError) as error:
                logger.error("Network scan failed: %s", error)
            try:
                settings = get_settings()
                interval = max(1, int(settings["scan_interval"]))
            except (OSError, TypeError, ValueError) as error:
                logger.error("Unable to read scanner settings: %s", error)
                interval = SCAN_EVERY
            self.stop_event.wait(interval)
        self.running = False
