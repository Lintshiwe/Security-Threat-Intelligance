import os
import sys
import psutil
import win32gui
import win32process
import win32con
import win32api
import wmi
import time
import logging
from datetime import datetime
from colorama import init, Fore, Style
import pandas as pd
import json
import hashlib
import requests
import datetime

import threading

# Optional imports for network features
SCAPY_AVAILABLE = False
NETIFACES_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    pass
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    pass

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog

# Initialize colorama for colored output (for console fallback)
init()

VIRUSTOTAL_API_KEY = "0e5e3afe6dd5dd1c4b3b4207a869dec462ebe73ef997b06f67617dabee82acf9"
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

# --- VirusTotal helpers ---
def vt_get_file_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash
    except Exception:
        return None

def vt_check_file(hash):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url = VIRUSTOTAL_FILE_URL.format(hash)
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return malicious, suspicious
        else:
            return None, None
    except Exception:
        return None, None

def vt_check_ip(ip):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url = VIRUSTOTAL_IP_URL.format(ip)
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return malicious, suspicious
        else:
            return None, None
    except Exception:
        return None, None

class ThreatMonitor:
    def __init__(self, gui_callback=None):
        self.wmi = wmi.WMI()
        self.known_processes = {}
        self.threat_database = self.load_threat_database()
        self.setup_logging()
        self.gui_callback = gui_callback  # Function to call when a threat is detected
        self.running = True
        
    def setup_logging(self):
        logging.basicConfig(
            filename='security_threats.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def load_threat_database(self):
        try:
            with open('threat_database.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default threat indicators if database doesn't exist
            return {
                "suspicious_paths": [
                    "\\temp\\", "\\downloads\\",
                    "\\appdata\\local\\temp\\"
                ],
                "suspicious_connections": [
                    "0.0.0.0", "127.0.0.1"
                ],
                "high_risk_processes": [
                    "cmd.exe", "powershell.exe"
                ]
            }

    def get_process_details(self, pid):
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'username': process.username(),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'connections': process.net_connections(),
                'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def analyze_process(self, process_details):
        if not process_details:
            return 0
        
        risk_score = 0
        
        # Check suspicious paths
        exe_path = process_details['exe'].lower()
        for sus_path in self.threat_database['suspicious_paths']:
            if sus_path in exe_path:
                risk_score += 2
                
        # Check high risk processes
        if process_details['name'].lower() in self.threat_database['high_risk_processes']:
            risk_score += 2
            
        # Check network connections
        for conn in process_details['connections']:
            if conn.status == 'ESTABLISHED':
                if str(conn.raddr.ip) in self.threat_database['suspicious_connections']:
                    risk_score += 3
                    
        # Check resource usage
        if process_details['cpu_percent'] > 80:
            risk_score += 1
        if process_details['memory_percent'] > 80:
            risk_score += 1
            
        return risk_score

    def terminate_process(self, pid):
        try:
            process = psutil.Process(pid)
            process.terminate()
            logging.info(f"Terminated suspicious process: {process.name()} (PID: {pid})")
            print(f"{Fore.RED}[!] Terminated suspicious process: {process.name()} (PID: {pid}){Style.RESET_ALL}")
            return True
        except:
            logging.error(f"Failed to terminate process with PID: {pid}")
            return False


    def monitor_system(self):
        if not self.gui_callback:
            print(f"{Fore.GREEN}[+] Starting Security Threat Intelligence Monitor...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Press Ctrl+C to stop monitoring{Style.RESET_ALL}")
        
        while self.running:
            try:
                # Get all running processes
                for process in psutil.process_iter(['pid', 'name']):
                    pid = process.info['pid']
                    # Skip if we've already analyzed this process recently
                    if pid in self.known_processes and \
                       time.time() - self.known_processes[pid]['last_check'] < 60:
                        continue
                    # Get detailed process information
                    process_details = self.get_process_details(pid)
                    if not process_details:
                        continue
                    # Analyze the process for potential threats
                    risk_score = self.analyze_process(process_details)
                    # Update known processes
                    self.known_processes[pid] = {
                        'last_check': time.time(),
                        'risk_score': risk_score
                    }
                    # Handle high-risk and suspicious processes
                    if risk_score >= 3:
                        threat_info = {
                            'pid': pid,
                            'name': process_details['name'],
                            'exe': process_details['exe'],
                            'risk_score': risk_score,
                            'status': 'High-Risk' if risk_score >= 5 else 'Suspicious'
                        }
                        if self.gui_callback:
                            self.gui_callback(threat_info)
                        else:
                            msg = f"High-risk process detected!\n" \
                                  f"Process: {process_details['name']}\n" \
                                  f"PID: {pid}\n" \
                                  f"Path: {process_details['exe']}\n" \
                                  f"Risk Score: {risk_score}"
                            print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")
                            logging.warning(msg)
                            if risk_score >= 5:
                                if input(f"{Fore.YELLOW}Do you want to terminate this process? (y/n): {Style.RESET_ALL}").lower() == 'y':
                                    self.terminate_process(pid)
                    # Sleep for a short duration to prevent high CPU usage
                time.sleep(1)
            except KeyboardInterrupt:
                self.running = False
                if not self.gui_callback:
                    print(f"{Fore.GREEN}[+] Stopping Security Threat Intelligence Monitor...{Style.RESET_ALL}")
                break
            except Exception as e:
                logging.error(f"Error in monitoring: {str(e)}")
                if not self.gui_callback:
                    print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
                continue


import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_router_and_devices():
    if not (NETIFACES_AVAILABLE and SCAPY_AVAILABLE):
        return None, []
    gateways = netifaces.gateways()
    router_ip = gateways.get('default', {}).get(netifaces.AF_INET, [None])[0]
    devices = []
    if router_ip:
        ip_range = router_ip.rsplit('.', 1)[0] + '.1/24'
        try:
            # Use scapy to ARP scan the subnet for all devices
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=0)
            for snd, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                # Try to resolve hostname
                try:
                    import socket
                    name = socket.gethostbyaddr(ip)[0]
                except Exception:
                    name = ip
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'name': name
                })
        except Exception:
            pass
    return router_ip, devices

# --- Advanced analytics helpers for network map ---
device_last_seen = {}
def lookup_vendor(mac):
    try:
        import requests
        resp = requests.get(f'https://api.macvendors.com/{mac}', timeout=2)
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return "Unknown"
def guess_type(name, vendor):
    name = name.lower()
    vendor = vendor.lower()
    if "router" in name or "gateway" in name:
        return "Router"
    if any(x in vendor for x in ["intel", "realtek", "broadcom", "atheros"]):
        return "PC/NIC"
    if any(x in vendor for x in ["apple", "samsung", "android", "huawei", "xiaomi"]):
        return "Mobile"
    if any(x in vendor for x in ["printer", "hp inc", "canon", "epson"]):
        return "Printer"
    if any(x in vendor for x in ["camera", "hikvision", "dahua"]):
        return "Camera"
    return "Unknown"

# --- GUI Entrypoint ---
def run_gui():
    root = tk.Tk()
    root.title("Security Threat Intelligence Monitor")
    root.geometry("950x550")
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('Treeview', rowheight=28, font=('Segoe UI', 10))
    style.configure('Treeview.Heading', font=('Segoe UI', 11, 'bold'))

    # Tabs
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    # --- Process Threats Tab ---
    process_frame = ttk.Frame(notebook)
    notebook.add(process_frame, text='Process Threats')
    status_var = tk.StringVar(value="Status: Monitoring (Running in Background)")
    status_label = ttk.Label(process_frame, textvariable=status_var, anchor="w")
    status_label.pack(fill=tk.X, padx=5, pady=2)

    columns = ("PID", "Name", "Path", "Risk Score", "Status", "VT File", "VT IP", "Suspicious Network", "Action")
    tree = ttk.Treeview(process_frame, columns=columns, show="headings", height=15)
    for col in columns:
        tree.heading(col, text=col)
        if col == "Path":
            tree.column(col, width=220)
        elif col == "Suspicious Network":
            tree.column(col, width=180)
        elif col == "VT File" or col == "VT IP":
            tree.column(col, width=90)
        elif col == "Action":
            tree.column(col, width=140)
        else:
            tree.column(col, width=90)
    tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # --- Network Tab ---
    network_frame = ttk.Frame(notebook)
    notebook.add(network_frame, text='Network Activity')
    net_columns = ("PID", "Process", "Local Address", "Remote Address", "Status", "Suspicious", "VT IP")
    net_tree = ttk.Treeview(network_frame, columns=net_columns, show="headings", height=15)
    for col in net_columns:
        net_tree.heading(col, text=col)
        if col == "Remote Address":
            net_tree.column(col, width=200)
        elif col == "VT IP":
            net_tree.column(col, width=90)
        else:
            net_tree.column(col, width=120)
    net_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # --- Network Packet Tab ---
    packet_frame = ttk.Frame(notebook)
    notebook.add(packet_frame, text='Network Packets')
    pkt_columns = ("Time", "Source", "Destination", "Protocol", "Info", "Threat")
    pkt_tree = ttk.Treeview(packet_frame, columns=pkt_columns, show="headings", height=15)
    for col in pkt_columns:
        pkt_tree.heading(col, text=col)
        pkt_tree.column(col, width=120 if col!="Info" else 220)
    pkt_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    if not SCAPY_AVAILABLE:
        pkt_tree.insert("", 0, values=("-", "-", "-", "-", "Install scapy for packet capture", "-"))

    # Human-readable packet details popup
    def show_packet_details(event):
        item = pkt_tree.identify_row(event.y)
        if not item:
            return
        values = pkt_tree.item(item)['values']
        details = f"Time: {values[0]}\nSource: {values[1]}\nDestination: {values[2]}\nProtocol: {values[3]}\nInfo: {values[4]}\nThreat: {values[5]}"
        try:
            idx = pkt_tree.index(item)
            if 'captured_packets' in globals() and idx < len(captured_packets):
                pkt = captured_packets[idx]
                from scapy.all import hexdump
                details += "\n\nRaw Packet (hex):\n" + hexdump(pkt, dump=True)
                if pkt.haslayer('TCP'):
                    details += f"\nTCP Flags: {pkt['TCP'].flags} Seq: {pkt['TCP'].seq} Ack: {pkt['TCP'].ack}"
                if pkt.haslayer('UDP'):
                    details += f"\nUDP Len: {pkt['UDP'].len}"
                if pkt.haslayer('Raw'):
                    raw = pkt['Raw'].load
                    try:
                        details += f"\nPayload: {raw.decode(errors='replace')}"
                    except Exception:
                        details += f"\nPayload: {raw}"
        except Exception:
            pass
        messagebox.showinfo("Packet Details", details)

    pkt_tree.bind("<Double-1>", show_packet_details)


    # --- Network Map Tab ---
    map_frame = ttk.Frame(notebook)
    notebook.add(map_frame, text='Network Map')
    map_label = ttk.Label(map_frame, text="(Admin required) Displays router and connected devices.", font=("Segoe UI", 10))
    map_label.pack(pady=5)
    analytics_var = tk.StringVar(value="")
    analytics_label = ttk.Label(map_frame, textvariable=analytics_var, font=("Segoe UI", 10, "italic"), foreground="#444")
    analytics_label.pack(pady=2)
    map_columns = ("IP", "MAC", "Name", "Vendor", "Type", "Last Seen")
    map_tree = ttk.Treeview(map_frame, columns=map_columns, show="headings", height=15)
    for col in map_columns:
        map_tree.heading(col, text=col)
        map_tree.column(col, width=140 if col!="Name" else 180)
    map_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    # Always enable the button, check for modules at click time
    map_btn = ttk.Button(map_frame, text="Scan Network", state=tk.NORMAL)
    map_btn.pack(pady=5)
    def check_network_libs():
        missing = []
        try:
            import scapy.all
        except ImportError:
            missing.append('scapy')
        try:
            import netifaces
        except ImportError:
            missing.append('netifaces')
        return missing
    if check_network_libs():
        map_tree.insert("", 0, values=("-", "-", "-", "-", "-", "Install netifaces & scapy for network map"))

    # --- Controls ---
    control_frame = ttk.Frame(root)
    control_frame.pack(fill=tk.X, padx=5, pady=2)
    pause_var = tk.BooleanVar(value=False)
    def toggle_pause():
        pause_var.set(not pause_var.get())
        if pause_var.get():
            status_var.set("Status: Monitoring Paused")
        else:
            status_var.set("Status: Monitoring (Running in Background)")

    pause_btn = ttk.Button(control_frame, text="Pause/Resume", command=toggle_pause)
    pause_btn.pack(side=tk.LEFT, padx=2)
    export_btn = ttk.Button(control_frame, text="Export Threats", command=lambda: export_threats(tree))
    export_btn.pack(side=tk.LEFT, padx=2)
    refresh_btn = ttk.Button(control_frame, text="Refresh Network", command=lambda: update_network_tab())
    refresh_btn.pack(side=tk.LEFT, padx=2)

    # Store threats by PID
    threats = {}

    def gui_callback(threat_info):
        if pause_var.get():
            return
        pid = threat_info['pid']
        if pid not in threats or threats[pid]['risk_score'] != threat_info['risk_score']:
            threats[pid] = threat_info
            # Insert or update row
            for item in tree.get_children():
                if tree.item(item)['values'][0] == pid:
                    tree.delete(item)
            vt_file = vt_ip = "-"
            # Show VT results if available
            vt_file_mal = threat_info.get('vt_file_malicious')
            vt_file_susp = threat_info.get('vt_file_suspicious')
            if vt_file_mal is not None or vt_file_susp is not None:
                vt_file = f"M:{vt_file_mal or 0}/S:{vt_file_susp or 0}"
            vt_ip_mal = threat_info.get('vt_ip_malicious')
            vt_ip_susp = threat_info.get('vt_ip_suspicious')
            if vt_ip_mal is not None or vt_ip_susp is not None:
                vt_ip = f"M:{vt_ip_mal or 0}/S:{vt_ip_susp or 0}"

            # Gather suspicious network info for this process
            suspicious_networks = []
            try:
                proc = psutil.Process(pid)
                for conn in proc.net_connections():
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = str(conn.raddr.ip)
                        remote_port = str(conn.raddr.port)
                        if remote_ip in monitor.threat_database.get('suspicious_connections', []):
                            suspicious_networks.append(f"{remote_ip}:{remote_port}")
            except Exception:
                pass
            sus_net_summary = ", ".join(suspicious_networks) if suspicious_networks else "-"
            # Show both actions if both are relevant
            actions = []
            if threat_info['risk_score'] >= 5:
                actions.append("Terminate")
            if suspicious_networks:
                actions.append("Network Actions")
            action_text = ", ".join(actions) if actions else "-"
            tree.insert("", "end", values=(pid, threat_info['name'], threat_info['exe'], threat_info['risk_score'], threat_info['status'], vt_file, vt_ip, sus_net_summary, action_text))

    # Initialize monitor before any callback uses it
    monitor = ThreatMonitor(gui_callback=gui_callback)
    monitor_thread = threading.Thread(target=monitor.monitor_system, daemon=True)
    monitor_thread.start()

    def on_tree_click(event):
        item = tree.identify_row(event.y)
        if not item:
            return
        values = tree.item(item)['values']
        pid, name, exe, risk_score, status, vt_file, vt_ip, sus_net, action = values
        actions = [a.strip() for a in action.split(",")]
        # Show context menu on right-click, or handle double-click as before
        def show_context_menu(event):
            menu = tk.Menu(root, tearoff=0)
            if "Terminate" in actions:
                menu.add_command(label="Terminate Process", command=lambda: terminate_selected())
            if "Network Actions" in actions and sus_net != "-":
                menu.add_command(label="Network Actions", command=lambda: show_network_actions_popup(pid, name, sus_net))
            menu.post(event.x_root, event.y_root)

        def terminate_selected():
            if messagebox.askyesno("Terminate Process", f"Terminate {name} (PID: {pid})?"):
                monitor.terminate_process(pid)
                tree.delete(item)
                del threats[pid]

        # On double-click, show context menu for user to pick action
        show_context_menu(event)

    # Bind right-click and double-click to show context menu
    tree.bind("<Button-3>", on_tree_click)  # Right-click
    tree.bind("<Double-1>", on_tree_click)  # Double-click

    def show_network_actions_popup(pid, name, sus_net):
        popup = tk.Toplevel(root)
        popup.title(f"Network Actions for {name} (PID: {pid})")
        popup.geometry("420x260")
        label = ttk.Label(popup, text=f"Suspicious Network Connections for {name} (PID: {pid}):", font=("Segoe UI", 10, "bold"))
        label.pack(pady=5)
        sus_list = sus_net.split(", ")
        listbox = tk.Listbox(popup, height=6, selectmode=tk.SINGLE)
        for net in sus_list:
            listbox.insert(tk.END, net)
        listbox.pack(fill=tk.X, padx=10, pady=5)

        def do_vt_lookup():
            sel = listbox.curselection()
            if not sel:
                messagebox.showinfo("Lookup", "Select a network connection.")
                return
            ip = listbox.get(sel[0]).split(":")[0]
            mal, susp = vt_check_ip(ip)
            messagebox.showinfo("VirusTotal IP Lookup", f"IP: {ip}\nMalicious: {mal or 0}\nSuspicious: {susp or 0}")

        def do_block():
            sel = listbox.curselection()
            if not sel:
                messagebox.showinfo("Block", "Select a network connection.")
                return
            ip = listbox.get(sel[0]).split(":")[0]
            # Block using Windows Firewall (netsh)
            import subprocess
            rule_name = f"Block_{pid}_{ip}"
            exe = None
            # Find exe for this pid
            try:
                exe = psutil.Process(pid).exe()
            except Exception:
                exe = None
            try:
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=out", f"remoteip={ip}", "action=block"]
                if exe:
                    cmd.insert(8, f"program={exe}")
                subprocess.run(cmd, check=True, capture_output=True)
                messagebox.showinfo("Block", f"Blocked outbound traffic to {ip} for process {name}.")
            except Exception as e:
                messagebox.showerror("Block", f"Failed to block: {e}")

        def do_quarantine():
            sel = listbox.curselection()
            if not sel:
                messagebox.showinfo("Quarantine", "Select a network connection.")
                return
            ip = listbox.get(sel[0]).split(":")[0]
            # Quarantine: block both in/out for this process and IP
            import subprocess
            rule_name = f"Quarantine_{pid}_{ip}"
            exe = None
            try:
                exe = psutil.Process(pid).exe()
            except Exception:
                exe = None
            try:
                cmd_out = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=out", f"remoteip={ip}", "action=block"]
                cmd_in = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_in", "dir=in", f"remoteip={ip}", "action=block"]
                if exe:
                    cmd_out.insert(8, f"program={exe}")
                    cmd_in.insert(8, f"program={exe}")
                subprocess.run(cmd_out, check=True, capture_output=True)
                subprocess.run(cmd_in, check=True, capture_output=True)
                messagebox.showinfo("Quarantine", f"Quarantined {ip} for process {name} (blocked in/out).")
            except Exception as e:
                messagebox.showerror("Quarantine", f"Failed to quarantine: {e}")

        btn_frame = ttk.Frame(popup)
        btn_frame.pack(pady=10)
        vt_btn = ttk.Button(btn_frame, text="VirusTotal Lookup", command=do_vt_lookup)
        vt_btn.pack(side=tk.LEFT, padx=5)
        block_btn = ttk.Button(btn_frame, text="Block Network", command=do_block)
        block_btn.pack(side=tk.LEFT, padx=5)
        quar_btn = ttk.Button(btn_frame, text="Quarantine", command=do_quarantine)
        quar_btn.pack(side=tk.LEFT, padx=5)
        close_btn = ttk.Button(btn_frame, text="Close", command=popup.destroy)
        close_btn.pack(side=tk.LEFT, padx=5)

    # --- Network Tab Logic ---
    vt_ip_cache = {}
    def show_ip_info(ip):
        if not ip or ip in ("-", "127.0.0.1", "0.0.0.0"): 
            messagebox.showinfo("IP Info", "No valid remote IP selected.")
            return
        if ip in vt_ip_cache:
            mal, susp = vt_ip_cache[ip]
        else:
            mal, susp = vt_check_ip(ip)
            vt_ip_cache[ip] = (mal, susp)
        info = f"IP: {ip}\nMalicious: {mal or 0}\nSuspicious: {susp or 0}"
        messagebox.showinfo("VirusTotal IP Info", info)

    def update_network_tab():
        for item in net_tree.get_children():
            net_tree.delete(item)
        suspicious_ips = set(monitor.threat_database.get('suspicious_connections', []))
        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.info['pid']
            name = proc.info['name']
            try:
                for conn in psutil.Process(pid).net_connections():
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                    status = conn.status
                    suspicious = "Yes" if conn.raddr and str(conn.raddr.ip) in suspicious_ips else ""
                    vt_ip = "-"
                    row_tags = ()
                    if suspicious:
                        row_tags = ('suspicious',)
                    idx = net_tree.insert("", "end", values=(pid, name, laddr, raddr, status, suspicious, vt_ip), tags=row_tags)
            except Exception:
                continue
        net_tree.tag_configure('suspicious', background='#ffcccc')

    def on_network_row(event):
        item = net_tree.identify_row(event.y)
        if not item:
            return
        values = net_tree.item(item)['values']
        raddr = values[3]
        ip = raddr.split(':')[0] if raddr else ""
        show_ip_info(ip)

    net_tree.bind("<Double-1>", on_network_row)

    # Add a button for manual IP info lookup
    ipinfo_btn = ttk.Button(control_frame, text="IP Info Lookup", command=lambda: show_ip_info(net_tree.item(net_tree.focus())['values'][3].split(':')[0] if net_tree.focus() else ""))
    ipinfo_btn.pack(side=tk.LEFT, padx=2)

    # --- Export Threats ---
    def export_threats(tree_widget):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not file_path:
            return
        import csv
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["PID", "Name", "Path", "Risk Score", "Status"])
            for item in tree_widget.get_children():
                row = tree_widget.item(item)['values'][:5]
                writer.writerow(row)
        messagebox.showinfo("Export", f"Threats exported to {file_path}")

    # --- Network Packet Tab Logic ---
    if SCAPY_AVAILABLE:
        import queue
        pkt_queue = queue.Queue()
        captured_packets = []  # Store for human-readable inspection
        def packet_callback(pkt):
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
                info = ""
                threat = ""
                if TCP in pkt:
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                    info = f"TCP {sport}->{dport}"
                    if dport in [23, 2323, 4444, 3389]:
                        threat = "Suspicious Port"
                elif UDP in pkt:
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                    info = f"UDP {sport}->{dport}"
                else:
                    info = proto_name
                pkt_queue.put((src, dst, proto_name, info, threat))
                captured_packets.insert(0, pkt)
                if len(captured_packets) > 2000:
                    captured_packets.pop()

        def process_packet_queue():
            try:
                while True:
                    src, dst, proto_name, info, threat = pkt_queue.get_nowait()
                    values = (time.strftime('%H:%M:%S'), src, dst, proto_name, info, threat)
                    pkt_tree.insert("", 0, values=values)
                    if threat:
                        pkt_tree.item(pkt_tree.get_children()[0], tags=('threat',))
                        pkt_tree.tag_configure('threat', background='#ffcccc')
            except queue.Empty:
                pass
            root.after(200, process_packet_queue)

        def start_sniffing():
            sniff(prn=packet_callback, store=0)

        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
        root.after(200, process_packet_queue)

    # --- Network Map Logic ---
    def scan_network():
        map_tree.delete(*map_tree.get_children())
        analytics_var.set("")
        missing = check_network_libs()
        if missing:
            map_tree.insert("", 0, values=('-', '-', '-', '-', '-', f"Install {' & '.join(missing)} for network map"))
            return
        router_ip, devices = get_router_and_devices()
        device_count = 0
        type_counts = {}
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if router_ip:
            map_tree.insert("", "end", values=(router_ip, '', 'Router', 'N/A', 'Router', now))
            device_last_seen[router_ip] = now
            type_counts['Router'] = 1
            device_count += 1
        for dev in devices:
            if dev['ip'] != router_ip:
                mac = dev['mac']
                name = dev['name']
                vendor = lookup_vendor(mac)
                dtype = guess_type(name, vendor)
                last_seen = now
                device_last_seen[dev['ip']] = last_seen
                map_tree.insert("", "end", values=(dev['ip'], mac, name, vendor, dtype, last_seen))
                type_counts[dtype] = type_counts.get(dtype, 0) + 1
                device_count += 1
        if not device_count:
            messagebox.showinfo("Scan", "No devices found or admin rights required.")
        else:
            analytics = f"Devices: {device_count} | " + ", ".join(f"{k}: {v}" for k,v in type_counts.items())
            analytics_var.set(analytics)

    map_btn.config(command=scan_network)

    def on_close():
        monitor.running = False
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    update_network_tab()
    root.mainloop()

if __name__ == "__main__":
    run_gui()
