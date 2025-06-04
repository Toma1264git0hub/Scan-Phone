import os
import time
import socket
from rich.console import Console

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
RESET = "\033[0m"

Tomas_console = Console()

Tomas_logo = f"""
───────█████████████████████
────████▀─────────────────▀████
──███▀───────────────────────▀███
─██▀───────────────────────────▀██
█▀───────────────────────────────▀█
█─────────────────────────────────█
█─────────────────────────────────█
█─────────────────────────────────█
█───█████─────────────────█████───█
█──██▓▓▓███─────────────███▓▓▓██──█
█──██▓▓▓▓▓██───────────██▓▓▓▓▓██──█
█──██▓▓▓▓▓▓██─────────██▓▓▓▓▓▓██──█
█▄──████▓▓▓▓██───────██▓▓▓▓████──▄█
▀█▄───▀███▓▓▓██─────██▓▓▓███▀───▄█▀
──█▄────▀█████▀─────▀█████▀────▄█
─▄██───────────▄█─█▄───────────██▄
─███───────────██─██───────────███
─███───────────────────────────███
──▀██──██▀██──█──█──█──██▀██──██▀
───▀████▀─██──█──█──█──██─▀████▀
────▀██▀──██──█──█──█──██──▀██▀
──────────██──█──█──█──██
──────────██──█──█──█──██
──────────██──█──█──█──██
──────────██──█──█──█──██
──────────██──█──█──█──██
──────────██──█──█──█──██
──────────██──█──█──█──██
──────────██──█──█──█──██
──────────██──█──█──█──██
──────────██──█──█──█──██
───────────█▄▄█▄▄█▄▄█▄▄█

{M}programmer
TELEGRAM: @K_DKP
TIKTOK: @.html.1
GITHUB: @toma1264git0hub
{RESET}
"""

def Tomas_get_installed_apps():
    try:
        output = os.popen("pm list packages").read()
        packages = [line.replace("package:", "").strip() for line in output.splitlines()]
        return packages
    except Exception as e:
        Tomas_console.print(f"{R}Error getting packages: {e}{RESET}")
        return []

def Tomas_analyze_app(Tomas_pkg):
    perms = os.popen(f"dumpsys package {Tomas_pkg} | grep permission").read().splitlines()
    Tomas_suspicious = []

    for Tomas_perm in perms:
        if any(x in Tomas_perm for x in [
            "INTERNET", "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
            "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_CONTACTS",
            "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG"
        ]):
            Tomas_suspicious.append(Tomas_perm.strip())

    return Tomas_suspicious

def Tomas_scan_ports(ip):
    ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        443: "HTTPS",
        445: "Microsoft-DS",
        3389: "RDP",
        8080: "HTTP Proxy"
    }
    Tomas_console.print(f"\n{Y}Starting port scan on {ip}:{RESET}\n")

    for port, name in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        if result == 0:
            Tomas_console.print(f"{G}{ip} | Port {port} ({name}) is OPEN ✅{RESET}")
        else:
            Tomas_console.print(f"{R}{ip} | Port {port} ({name}) is CLOSED ⛔{RESET}")
        sock.close()

def Tomas_main():
    print(Tomas_logo)
    Tomas_console.print("[bold cyan]Starting suspicious permission scan...[/]")

    Tomas_apps = Tomas_get_installed_apps()
    Tomas_console.print(f"[green]Found {len(Tomas_apps)} installed apps.[/green]\n")

    Tomas_results = {}
    for Tomas_pkg in Tomas_apps:
        suspicious = Tomas_analyze_app(Tomas_pkg)
        if suspicious:
            Tomas_results[Tomas_pkg] = suspicious

    Tomas_console.print(f"\n{M}Suspicious Apps and Permissions:{RESET}")
    if not Tomas_results:
        Tomas_console.print("[bold green]No suspicious apps found![/bold green]")
    else:
        for app, perms in Tomas_results.items():
            Tomas_console.print(f"\n[bold red]{app}[/bold red]")
            for perm in perms:
                Tomas_console.print(f"  [red]- {perm}[/red]")

  
    ip = input("\nEnter IP address to scan ports: ")
    Tomas_scan_ports(ip)

    Tomas_console.print("\n[bold cyan]Scan complete![/bold cyan]")

if __name__ == "__main__":
    Tomas_main()