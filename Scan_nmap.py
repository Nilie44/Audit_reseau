import netifaces
import ipaddress
import subprocess
import sqlite3
import pandas as pd

# --- Fonction pour récupérer l’interface par défaut
def get_default_interfaces():
    gws = netifaces.gateways()
    default_iface = gws.get('default', {}).get(netifaces.AF_INET)
    if default_iface:
        return default_iface[1]
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        inet_info = addrs.get(netifaces.AF_INET)
        if inet_info:
            
            ip = inet_info[0].get('addr')
            if ip and not ip.startswith("127."):
                return iface
    return None

# --- Fonction pour récupérer l’adresse réseau
def get_network_address():
    iface = get_default_interfaces()
    if not iface:
        print("Impossible de trouver l'interface réseau par défaut")
        return None

    addrs = netifaces.ifaddresses(iface)
    inet_info = addrs.get(netifaces.AF_INET)
    if not inet_info:
        print(f"Pas d'adresse IPv4 sur l'interface {iface}")
        return None

    ip = inet_info[0]['addr']
    netmask = inet_info[0]['netmask']
    interface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
    return str(interface.network)

# --- Fonction pour scanner le réseau et obtenir IP, MAC, ports et services
def scan_and_save_details(network):
    print(f"🔎 Scan du réseau {network} en cours...")

    # Exécuter nmap avec détection d’OS, services, et ping
    try:
        # -O pour OS, -sV pour services, -p- pour tous les ports
        result = subprocess.run(["nmap", "-sV", network], capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print(" Erreur d'exécution de Nmap")
            print(result.stderr)
            return

        # On va parser la sortie
        hosts_data = []
        current_ip = None
        current_mac = "N/A"
        open_ports = []

        for line in result.stdout.splitlines():
            line = line.strip()
            # Détecter les hosts
            if line.startswith("Nmap scan report for"):
                # Sauvegarder le précédent host avant de réinitialiser
                if current_ip:
                    hosts_data.append({
                        "IP": current_ip,
                        "MAC": current_mac,
                        "Ports_ouverts": ", ".join([p[0] for p in open_ports]),
                        "Services": ", ".join([p[1] for p in open_ports])
                    })
                # Nouveau host
                parts = line.split()
                current_ip = parts[-1].strip("()")
                current_mac = "N/A"
                open_ports = []

            # Détecter la MAC address
            elif "MAC Address:" in line:
                mac_info = line.split("MAC Address:")[1].strip()
                current_mac = mac_info.split(" ")[0]

            # Détecter les lignes de port ouvert (commencent souvent par un numéro de port)
            elif line and ("/tcp" in line or "/udp" in line):
                cols = line.split()
                port = cols[0]  # ex: 80/tcp
                service = cols[2] if len(cols) >= 3 else "?"
                open_ports.append((port, service))

        # Ajouter le dernier host
        if current_ip:
            hosts_data.append({
                "IP": current_ip,
                "MAC": current_mac,
                "Ports_ouverts": ", ".join([p[0] for p in open_ports]),
                "Services": ", ".join([p[1] for p in open_ports])
            })

        return hosts_data      
      
    except FileNotFoundError:
        print("Nmap n'est pas installé ou introuvable.")
        return []

def save_to_sqlite(data, db_path= "myDB.db", table_name = "scan_nmap2" ):
    df = pd.DataFrame(data)
    conn = sqlite3.connect(db_path)

    df.to_sql( table_name, conn, if_exists='replace', index=False)
    conn.close()
    print(f"Le fichier est enregistré dans la table {table_name}, de {db_path}")



if __name__ == "__main__":
    network = get_network_address()
    if network:
        data=scan_and_save_details(network)
        if data:
            save_to_sqlite(data, db_path="myDB.db", table_name="scan_nmap2")



        
