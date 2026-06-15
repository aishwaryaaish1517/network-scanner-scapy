"""
GUI for the Advanced Network Scanner.
Features:
- Tkinter window with Scan button
- Live table view of discovered devices
- Export to CSV and HTML
- Live/auto-refresh mode (scans repeatedly every X seconds)
- Highlights NEW devices and shows DISCONNECTED devices during live mode
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import webbrowser
import os
import socket
from datetime import datetime

# Import our scanning engine
import scanner


class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Scanner - Scapy")
        self.root.geometry("900x550")
        self.root.configure(bg="#f4f6f9")

        # State variables
        self.live_mode = False          # is live/auto-refresh active?
        self.live_thread = None
        self.known_devices = {}         # track devices across scans (for live mode)
        self.last_results = []          # store last scan results for export

        self.build_ui()

    # ---------------------------------------------------------
    # UI LAYOUT
    # ---------------------------------------------------------
    def build_ui(self):
        # --- Top frame: inputs ---
        top_frame = tk.Frame(self.root, bg="#f4f6f9", pady=10)
        top_frame.pack(fill="x", padx=15)

        tk.Label(top_frame, text="Target IP Range:", bg="#f4f6f9",
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(top_frame, width=20, font=("Segoe UI", 10))
        self.ip_entry.insert(0, "192.168.1.0/24")
        self.ip_entry.grid(row=0, column=1, padx=5)

        tk.Label(top_frame, text="Ports (comma separated):", bg="#f4f6f9",
                 font=("Segoe UI", 10, "bold")).grid(row=0, column=2, sticky="w", padx=(15, 0))
        self.ports_entry = tk.Entry(top_frame, width=25, font=("Segoe UI", 10))
        self.ports_entry.insert(0, "21,22,23,53,80,443,3389,8080")
        self.ports_entry.grid(row=0, column=3, padx=5)

        tk.Label(top_frame, text="Refresh Interval (sec):", bg="#f4f6f9",
                 font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.interval_entry = tk.Entry(top_frame, width=10, font=("Segoe UI", 10))
        self.interval_entry.insert(0, "15")
        self.interval_entry.grid(row=1, column=1, sticky="w", pady=(8, 0))

        # --- Buttons frame ---
        btn_frame = tk.Frame(self.root, bg="#f4f6f9", pady=10)
        btn_frame.pack(fill="x", padx=15)

        self.scan_btn = tk.Button(btn_frame, text="🔍 Scan Now", bg="#1a73e8", fg="white",
                                   font=("Segoe UI", 10, "bold"), padx=15, pady=5,
                                   command=self.start_single_scan)
        self.scan_btn.pack(side="left", padx=5)

        self.live_btn = tk.Button(btn_frame, text="▶ Start Live Mode", bg="#27ae60", fg="white",
                                   font=("Segoe UI", 10, "bold"), padx=15, pady=5,
                                   command=self.toggle_live_mode)
        self.live_btn.pack(side="left", padx=5)

        self.csv_btn = tk.Button(btn_frame, text="📄 Export CSV", bg="#7f8c8d", fg="white",
                                  font=("Segoe UI", 10, "bold"), padx=15, pady=5,
                                  command=self.export_csv)
        self.csv_btn.pack(side="left", padx=5)

        self.html_btn = tk.Button(btn_frame, text="🌐 Export HTML Report", bg="#e67e22", fg="white",
                                   font=("Segoe UI", 10, "bold"), padx=15, pady=5,
                                   command=self.export_html)
        self.html_btn.pack(side="left", padx=5)

        # --- Status label ---
        self.status_label = tk.Label(self.root, text="Status: Idle", bg="#f4f6f9",
                                      font=("Segoe UI", 9, "italic"), fg="#555")
        self.status_label.pack(anchor="w", padx=15)

        # --- Table (Treeview) ---
        table_frame = tk.Frame(self.root)
        table_frame.pack(fill="both", expand=True, padx=15, pady=10)

        columns = ("ip", "mac", "vendor", "hostname", "ports", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)

        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("vendor", text="Vendor")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("ports", text="Open Ports")
        self.tree.heading("status", text="Status")

        self.tree.column("ip", width=120)
        self.tree.column("mac", width=150)
        self.tree.column("vendor", width=170)
        self.tree.column("hostname", width=150)
        self.tree.column("ports", width=140)
        self.tree.column("status", width=100)

        # Color tags for status
        self.tree.tag_configure("new", background="#d4efdf")        # green
        self.tree.tag_configure("disconnected", background="#fadbd8")  # red
        self.tree.tag_configure("active", background="#ffffff")     # white

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ---------------------------------------------------------
    # SCANNING LOGIC
    # ---------------------------------------------------------
    def start_single_scan(self):
        """Runs one scan in a background thread (so GUI doesn't freeze)."""
        self.status_label.config(text="Status: Scanning... please wait")
        self.scan_btn.config(state="disabled")
        threading.Thread(target=self.perform_scan, daemon=True).start()

    def perform_scan(self, live=False):
        """
        Performs the actual scan using scanner.py functions.
        Compares with previous results if in live mode to detect new/disconnected devices.
        """
        ip_range = self.ip_entry.get().strip()
        try:
            ports = [int(p.strip()) for p in self.ports_entry.get().split(",") if p.strip()]
        except ValueError:
            self.show_error("Invalid port list. Use comma-separated numbers like 80,443")
            return

        try:
            results = scanner.run_full_scan(ip_range, ports)
        except Exception as e:
            self.show_error(f"Scan failed: {e}\n\nTip: Run VS Code/Terminal as Administrator.")
            return

        current_ips = {d["ip"]: d for d in results}

        # Determine status for each device (new / active / disconnected) - only matters in live mode
        display_results = []
        if live and self.known_devices:
            # Mark existing devices
            for ip, device in current_ips.items():
                if ip not in self.known_devices:
                    device["status"] = "NEW"
                else:
                    device["status"] = "ACTIVE"
                display_results.append(device)

            # Mark devices that disappeared
            for ip, old_device in self.known_devices.items():
                if ip not in current_ips:
                    old_device["status"] = "DISCONNECTED"
                    old_device["open_ports"] = old_device.get("open_ports", [])
                    display_results.append(old_device)
        else:
            for device in results:
                device["status"] = "ACTIVE"
                display_results.append(device)

        # Update known devices for next comparison
        self.known_devices = {d["ip"]: d for d in results}
        self.last_results = results  # store clean results (without status) for export

        # Update UI on main thread
        self.root.after(0, lambda: self.update_table(display_results))

    def update_table(self, results):
        """Refreshes the Treeview table with scan results."""
        self.tree.delete(*self.tree.get_children())

        for device in results:
            ports_str = ", ".join(map(str, device.get("open_ports", []))) or "None"
            status = device.get("status", "ACTIVE")

            tag = "active"
            if status == "NEW":
                tag = "new"
            elif status == "DISCONNECTED":
                tag = "disconnected"

            self.tree.insert("", "end", values=(
                device["ip"], device["mac"], device["vendor"],
                device["hostname"], ports_str, status
            ), tags=(tag,))

        count = sum(1 for d in results if d.get("status") != "DISCONNECTED")
        self.status_label.config(text=f"Status: Last scan complete — {count} active device(s) found "
                                        f"({datetime.now().strftime('%H:%M:%S')})")
        self.scan_btn.config(state="normal")

    # ---------------------------------------------------------
    # LIVE / AUTO-REFRESH MODE
    # ---------------------------------------------------------
    def toggle_live_mode(self):
        if not self.live_mode:
            try:
                interval = int(self.interval_entry.get())
                if interval < 5:
                    raise ValueError
            except ValueError:
                self.show_error("Refresh interval must be a number >= 5 seconds.")
                return

            self.live_mode = True
            self.live_btn.config(text="⏹ Stop Live Mode", bg="#c0392b")
            self.scan_btn.config(state="disabled")
            self.known_devices = {}  # reset history when starting live mode
            self.live_loop()
        else:
            self.live_mode = False
            self.live_btn.config(text="▶ Start Live Mode", bg="#27ae60")
            self.scan_btn.config(state="normal")
            self.status_label.config(text="Status: Live mode stopped")

    def live_loop(self):
        """Repeatedly scans every X seconds while live_mode is True."""
        if not self.live_mode:
            return

        self.status_label.config(text="Status: Live scanning... ")
        threading.Thread(target=lambda: self.perform_scan(live=True), daemon=True).start()

        try:
            interval = int(self.interval_entry.get())
        except ValueError:
            interval = 15

        # Schedule the next scan
        self.root.after(interval * 1000, self.live_loop)

    # ---------------------------------------------------------
    # EXPORT FUNCTIONS
    # ---------------------------------------------------------
    def export_csv(self):
        if not self.last_results:
            self.show_error("No scan results yet. Run a scan first.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = scanner.export_to_csv(self.last_results, f"scan_report_{timestamp}.csv")
        messagebox.showinfo("Export Successful", f"CSV report saved to:\n{filepath}")

    def export_html(self):
        if not self.last_results:
            self.show_error("No scan results yet. Run a scan first.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip_range = self.ip_entry.get().strip()
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        filepath = scanner.export_to_html(self.last_results, f"scan_report_{timestamp}.html",
                                           ip_range, scan_time)

        messagebox.showinfo("Export Successful", f"HTML report saved to:\n{filepath}\n\nOpening in browser...")
        webbrowser.open("file://" + os.path.realpath(filepath))

    # ---------------------------------------------------------
    # ERROR HANDLING
    # ---------------------------------------------------------
    def show_error(self, message):
        self.scan_btn.config(state="normal")
        self.status_label.config(text="Status: Error occurred")
        messagebox.showerror("Error", message)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
    