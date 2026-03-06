from flask import Flask, jsonify
import subprocess
import json

app = Flask(__name__)

import subprocess, re

def scan_wifi():
    output = subprocess.check_output(
        "netsh wlan show networks mode=bssid", 
        shell=True, 
        encoding="utf-8", 
        errors="ignore"
    )

    networks = []
    current = {}

    for line in output.splitlines():

        # SSID
        ssid_match = re.search(r"SSID \d+ : (.+)", line)
        if ssid_match:
            # save old SSID if exists
            if current:
                networks.append(current)
            current = {"ssid": ssid_match.group(1)}

        # Security authentication type
        auth_match = re.search(r"Authentication\s*:\s*(.+)", line)
        if auth_match:
            current["security"] = auth_match.group(1)

        # Signal strength %
        signal_match = re.search(r"Signal\s*:\s*(\d+)%", line)
        if signal_match:
            current["signal"] = int(signal_match.group(1))

    # push the last one
    if current:
        networks.append(current)

    # ----- RISK CALCULATION -----
    for net in networks:
        sec = net.get("security", "Unknown")
        sig = net.get("signal", 0)

        if "Open" in sec:
            risk = "HIGH"
        elif sig < 40:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        net["risk"] = risk

    # sort by nearest strongest wifi
    networks.sort(key=lambda x: x.get("signal", 0), reverse=True)

    return networks
