import tkinter as tk
from tkinter import ttk, messagebox
import asyncio
import aiohttp
import ipaddress
import logging
import time
import nmap  # For service version detection
import geoip2.database  # For geolocation

# ASCII Art
ASCII_ART = """
▄████▄▓██   ██▓ ▄▄▄▄   ▓█████  ██▀███    ██████  ▄████▄   ▄▄▄       ███▄    █     ██▓███   ██▀███   ▒█████  
▒██▀ ▀█ ▒██  ██▒▓█████▄ ▓█   ▀ ▓██ ▒ ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █    ▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒
▒▓█    ▄ ▒██ ██░▒██▒ ▄██▒███   ▓██ ░▄█ ▒░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒   ▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒
▒▓▓▄ ▄██▒░ ▐██▓░▒██░█▀  ▒▓█  ▄ ▒██▀▀█▄    ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒   ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░
▒ ▓███▀ ░░ ██▒▓░░▓█  ▀█▓░▒████▒░██▓ ▒██▒▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░   ▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░
░ ░▒ ▒  ░ ██▒▒▒ ░▒▓███▀▒░░ ▒░ ░░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒    ▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ 
  ░  ▒  ▓██ ░▒░ ▒░▒   ░  ░ ░  ░  ░▒ ░ ▒░░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░   ░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ 
░       ▒ ▒ ░░   ░    ░    ░     ░░   ░ ░  ░  ░  ░ ░            ░   ▒      ░   ░ ░    ░         ░░   ░ ░ ░ ░ ▒  
░ ░     ░ ░      ░         ░  ░   ░           ░  ░ ░            ░  ░         ░                ░         ░ ░  
░       ░ ░           ░                          ░                                                           
                                                                                                             
        CyberScan Pro (v1.0) - Lightning-Fast Port Scanner with Advanced Features
"""

# Set up logging
logging.basicConfig(filename="scan_report.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Dictionary to map common ports to their corresponding services
PORT_SERVICES = {
    20: "FTP Data (File Transfer Protocol - Data)",  # FTP data transfer
    21: "FTP Control (File Transfer Protocol - Control)",  # FTP control (command)
    22: "SSH (Secure Shell)",  # Secure Shell (SSH)
    23: "Telnet (Remote Login Service)",  # Telnet
    25: "SMTP (Simple Mail Transfer Protocol)",  # SMTP
    53: "DNS (Domain Name System)",  # DNS
    80: "HTTP (Hypertext Transfer Protocol)",  # HTTP
    110: "POP3 (Post Office Protocol version 3)",  # POP3
    115: "SFTP (Simple File Transfer Protocol)",  # SFTP
    123: "NTP (Network Time Protocol)",  # NTP
    143: "IMAP (Internet Message Access Protocol)",  # IMAP
    443: "HTTPS (HTTP over SSL/TLS)",  # HTTPS
    465: "SMTPS (SMTP over SSL/TLS)",  # SMTPS (SMTP over SSL/TLS)
    587: "SMTP (Mail Submission Protocol)",  # SMTP (Mail Submission Protocol)
    993: "IMAPS (IMAP over SSL/TLS)",  # IMAPS (IMAP over SSL/TLS)
    995: "POP3S (POP3 over SSL/TLS)",  # POP3S (POP3 over SSL/TLS)
    1433: "MSSQL (Microsoft SQL Server database server)",  # MSSQL
    1521: "Oracle (Oracle database default listener)",  # Oracle
    3306: "MySQL (MySQL database server)",  # MySQL
    3389: "RDP (Remote Desktop Protocol)",  # RDP
    5432: "PostgreSQL (PostgreSQL database server)",  # PostgreSQL
    5900: "VNC (Virtual Network Computing)",  # VNC
}

# List of known malicious ports for threat intelligence simulation
MALICIOUS_PORTS = {
    7: "Echo (Echo Protocol)",  # Echo protocol (used for testing and debugging)
    19: "Chargen (Character Generator Protocol)",  # Character generator protocol (used for testing and debugging)
    135: "Microsoft Windows RPC (Remote Procedure Call)",  # Microsoft Windows RPC
    137: "NetBIOS Name Service",  # NetBIOS Name Service
    138: "NetBIOS Datagram Service",  # NetBIOS Datagram Service
    139: "NetBIOS Session Service",  # NetBIOS Session Service
    445: "Microsoft-DS (SMB/CIFS)",  # Microsoft-DS (SMB/CIFS)
    1434: "Microsoft SQL Server browser service",  # Microsoft SQL Server browser service
    1900: "SSDP (Simple Service Discovery Protocol)",  # Simple Service Discovery Protocol (SSDP)
    5060: "SIP (Session Initiation Protocol)",  # Session Initiation Protocol (SIP)
    5061: "SIPS (Secure SIP)",  # Secure SIP (SIPS)
    6666: "IRC (Internet Relay Chat)",  # IRC (Internet Relay Chat)
    6667: "IRC (Internet Relay Chat)",  # IRC (Internet Relay Chat)
    6668: "IRC (Internet Relay Chat)",  # IRC (Internet Relay Chat)
    6669: "IRC (Internet Relay Chat)",  # IRC (Internet Relay Chat)
    7000: "Default port for some trojans",  # Default port for some trojans
    8080: "HTTP alternate (HTTP proxy server)",  # HTTP alternate (HTTP proxy server)
    8443: "HTTPS alternate (HTTPS for port 8080)",  # HTTPS alternate (HTTPS for port 8080)
    9999: "Unreal IRC Server (often Trojanized)",  # Unreal IRC Server (often Trojanized)
}

# Function to perform SYN scan on a port
async def syn_scan(ip, port, results_text):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{ip}:{port}", timeout=5) as response:
                if response.status == 200:
                    service = PORT_SERVICES.get(port, "Unknown")
                    if port in MALICIOUS_PORTS:
                        logging.warning(f"Potential threat detected on port {port} ({service})")
                        results_text.insert(tk.END, f"Open port found: {port} ({service})\n", "malicious")
                    else:
                        logging.info(f"Open port found: {port} ({service})")
                        results_text.insert(tk.END, f"Open port found: {port} ({service})\n")
    except Exception as e:
        pass

# Function to start SYN scan
async def start_syn_scan(ip, start_port, end_port, results_text):
    tasks = [syn_scan(ip, port, results_text) for port in range(start_port, end_port + 1)]
    await asyncio.gather(*tasks)

# Function to perform an intensive scan
def intensive_scan(ip, start_port, end_port, results_text):
    # Implement intensive scan logic here
    pass

# Function to perform a custom scan
def custom_scan(ip, start_port, end_port, results_text):
    # Implement custom scan logic here
    pass

# Function to start the scanning process
async def start_scan(ip, start_port, end_port, scan_mode, progress_var, results_text):
    open_ports = []
    start_time = time.time()

    if scan_mode == "SYN Scan":
        await start_syn_scan(ip, start_port, end_port, results_text)
    elif scan_mode == "Intensive Scan":
        intensive_scan(ip, start_port, end_port, results_text)
    elif scan_mode == "Custom Scan":
        custom_scan(ip, start_port, end_port, results_text)
    else:
        pass

    end_time = time.time()
    duration = end_time - start_time
    logging.info(f"Scan completed for {ip} in {duration:.2f} seconds. Open ports: {open_ports}")
    results_text.insert(tk.END, f"\nScan completed in {duration:.2f} seconds. Open ports: {open_ports}")
    messagebox.showinfo("Scan Complete", f"Scan completed successfully! Open ports: {open_ports}")

# Function to handle GUI events for starting a scan
async def start_scan_gui():
    ip = entry_ip.get()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid IP address.")
        return
    
    port_range = entry_port_range.get()
    try:
        start_port, end_port = map(int, port_range.split("-"))
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid port range in the format 'start_port-end_port'.")
        return

    scan_mode = scan_mode_var.get()
    
    if start_port <= end_port and 0 < start_port <= 65535 and 0 < end_port <= 65535:
        scan_button.config(state=tk.DISABLED)  # Disable scan button during scanning
        progress_var = tk.IntVar()
        progress_var.set(0)
        progress_window = tk.Toplevel()
        progress_window.title("Scanning Progress")
        progress_bar = ttk.Progressbar(progress_window, orient="horizontal", length=300, mode="determinate", variable=progress_var)
        progress_bar.pack(pady=20)
        results_text = tk.Text(progress_window, wrap=tk.WORD)
        results_text.pack(expand=True, fill=tk.BOTH)
        
        # Start the scanning process asynchronously
        try:
            await start_scan(ip, start_port, end_port, scan_mode, progress_var, results_text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    else:
        messagebox.showerror("Error", "Please enter a valid port range.")

# Function to clear the results text widget
def clear_results():
    results_text.delete(1.0, tk.END)

# Function to create a new scan
def new_scan():
    scan_button.config(state=tk.NORMAL)
    clear_results()

# Function to run the event loop
def run_event_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_forever()

# GUI
root = tk.Tk()
root.title("CyberScan Pro")

# Adjust window size according to ASCII art
lines = ASCII_ART.split("\n")
width = max(len(line) for line in lines)
height = len(lines)
root.geometry(f"{width * 8}x{height * 40}")

# Add ASCII Art Label
ascii_label = tk.Label(root, text=ASCII_ART, justify="left", anchor="nw", fg="blue", font=("Courier", 10))
ascii_label.pack(fill="both", expand=True)

label_ip = tk.Label(root, text="Enter IP:")
label_ip.pack()
entry_ip = tk.Entry(root)
entry_ip.pack()

label_port_range = tk.Label(root, text="Enter Port Range (e.g., 1-1000):")
label_port_range.pack()
entry_port_range = tk.Entry(root)
entry_port_range.pack()

scan_mode_var = tk.StringVar()
scan_mode_var.set("SYN Scan")  # Default to SYN Scan
scan_mode_frame = ttk.Frame(root)
scan_mode_frame.pack()
scan_mode_label = tk.Label(scan_mode_frame, text="Scan Mode:")
scan_mode_label.pack(side=tk.LEFT)
scan_mode_menu = ttk.OptionMenu(scan_mode_frame, scan_mode_var, "SYN Scan", "SYN Scan", "Intensive Scan", "Custom Scan")
scan_mode_menu.pack(side=tk.LEFT)

scan_button = tk.Button(root, text="Scan Ports", command=lambda: asyncio.create_task(start_scan_gui()))
scan_button.pack()

new_scan_button = tk.Button(root, text="New Scan", command=new_scan)
new_scan_button.pack()

# Define tag for highlighting malicious ports in red
results_text = tk.Text(root, wrap=tk.WORD)
results_text.tag_configure("malicious", foreground="red")
results_text.pack(expand=True, fill=tk.BOTH)

# Run the event loop
root.after(0, run_event_loop)
root.mainloop()