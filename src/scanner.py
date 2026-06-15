"""
Core scanning engine for the Network Scanner project.
Contains all logic for ARP scanning, vendor lookup, port scanning,
and report generation (CSV + HTML).
This file has NO terminal output - it's used by gui.py
"""

import scapy.all as scapy
import socket
import csv
import os
from datetime import datetime


def scan_network(ip_range):
    """
    Sends ARP requests to all IPs in the given range and listens for replies.
    Returns a list of dicts: [{"ip": ..., "mac": ...}, ...]
    """
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices_list = []
    for element in answered_list:
        devices_list.append({
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
        })
    return devices_list


def get_vendor(mac_address):
    """
    Looks up manufacturer using Scapy's built-in MAC vendor database (manuf file).
    Falls back to 'Unknown Vendor' if not found.
    """
    try:
        from scapy.layers.l2 import Ether
        # Scapy's manufdb has a lookup function
        vendor = scapy.conf.manufdb._get_manuf(mac_address)
        if vendor and vendor != mac_address:
            return vendor
        return "Unknown Vendor"
    except Exception:
        return "Unknown Vendor"
    

def get_hostname(ip):
    """
    Tries to resolve hostname for an IP. Returns 'Unknown' if it fails.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"


def scan_ports(ip, ports):
    """
    Checks which ports are open on a target IP using TCP connect attempts.
    Returns a list of open port numbers.
    """
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports


def run_full_scan(ip_range, ports):
    """
    Runs a complete scan: ARP discovery + vendor + hostname + port scan.
    Returns a list of result dicts ready for display/export.
    """
    devices = scan_network(ip_range)
    results = []

    for device in devices:
        vendor = get_vendor(device["mac"])
        hostname = get_hostname(device["ip"])
        open_ports = scan_ports(device["ip"], ports)

        results.append({
            "ip": device["ip"],
            "mac": device["mac"],
            "vendor": vendor,
            "hostname": hostname,
            "open_ports": open_ports
        })

    return results


def export_to_csv(results, filename):
    """
    Saves results to a CSV file in the output folder. Returns the file path.
    """
    os.makedirs("output", exist_ok=True)
    filepath = os.path.join("output", filename)

    with open(filepath, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["IP Address", "MAC Address", "Vendor", "Hostname", "Open Ports"])
        for device in results:
            writer.writerow([
                device["ip"],
                device["mac"],
                device["vendor"],
                device["hostname"],
                ", ".join(map(str, device["open_ports"])) or "None"
            ])

    return filepath


def export_to_html(results, filename, ip_range, scan_time):
    """
    Generates a styled HTML report and saves it to the output folder.
    Returns the file path.
    """
    os.makedirs("output", exist_ok=True)
    filepath = os.path.join("output", filename)

    # Build table rows
    rows_html = ""
    for device in results:
        ports_str = ", ".join(map(str, device["open_ports"])) or "None"
        port_badge_class = "open" if device["open_ports"] else "closed"
        rows_html += f"""
        <tr>
            <td>{device['ip']}</td>
            <td>{device['mac']}</td>
            <td>{device['vendor']}</td>
            <td>{device['hostname']}</td>
            <td><span class="badge {port_badge_class}">{ports_str}</span></td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Network Scan Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                background-color: #f4f6f9;
                margin: 0;
                padding: 30px;
                color: #2c3e50;
            }}
            .container {{
                max-width: 1000px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 10px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                padding: 30px;
            }}
            h1 {{
                color: #1a73e8;
                border-bottom: 3px solid #1a73e8;
                padding-bottom: 10px;
            }}
            .info {{
                background: #eaf1fb;
                padding: 12px 18px;
                border-radius: 6px;
                margin-bottom: 20px;
                font-size: 14px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            th, td {{
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #e0e0e0;
            }}
            th {{
                background-color: #1a73e8;
                color: white;
                text-transform: uppercase;
                font-size: 13px;
                letter-spacing: 0.5px;
            }}
            tr:hover {{
                background-color: #f5f9ff;
            }}
            .badge {{
                padding: 4px 10px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: bold;
            }}
            .badge.open {{
                background-color: #fde8e8;
                color: #c0392b;
            }}
            .badge.closed {{
                background-color: #e8f8ef;
                color: #27ae60;
            }}
            .footer {{
                margin-top: 20px;
                font-size: 12px;
                color: #999;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🌐 Network Scan Report</h1>
            <div class="info">
                <strong>Target Range:</strong> {ip_range} &nbsp; | &nbsp;
                <strong>Scan Time:</strong> {scan_time} &nbsp; | &nbsp;
                <strong>Devices Found:</strong> {len(results)}
            </div>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Vendor</th>
                    <th>Hostname</th>
                    <th>Open Ports</th>
                </tr>
                {rows_html}
            </table>
            <div class="footer">Generated by Advanced Network Scanner (Scapy + Tkinter)</div>
        </div>
    </body>
    </html>
    """

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    return filepath
