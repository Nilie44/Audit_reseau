#!/usr/bin/env python3
import netifaces #package des interface
import ipaddress #package des ips
import subprocess #permet de lancer une commande comme nmap, ls, ping, etc.

#fonction pour recuperer l'interface par défaut. 
def get_default_interfaces():
    gws = netifaces.gateways()
    default_iface = gws.get('default', {}).get(netifaces.AF_INET) #netifaces.AF_INET indique le type d'adresses
    
    #print("Gateways:",gws)
    #print("Default IPv4 route",default_iface)
    if default_iface:
        return default_iface[1]
    
    # pas de passerelle par défaut, chercher une interface ipv4 active non loopback
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        inet_info = addrs.get(netifaces.AF_INET)
        if inet_info:
            ip = inet_info[0].get('addr')
            if ip and not ip.startswith("127."):
                return iface

    # pas d'interface détectée
    return None
 
#fonction pour recuperer l'adresse du reseau
def get_network_address():
    iface = get_default_interfaces()
    
    if not iface:
        print("impossible de trouver l'interface réseau par défaut")
        return None
    
    addrs = netifaces.ifaddresses(iface) # addrs est une variable qui va stocker l'adresss ip associer a l'interface iface
    inet_info = addrs.get(netifaces.AF_INET) # net_info recupère l'adress, le masque et l'adresse de diffusion sous forme de liste de dictionnaire
    #print(inet_info)
    if not inet_info:
        print(f"pas d'adresse ipv4 sur l'interface{iface}")
        return None

    ip =  inet_info[0]['addr'] # pour recuperer une adresse, on doit d'abord choisi son indice sur la liste avant de renseigner la clé
    netmask = inet_info[0]['netmask']

    interface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
    network = interface.network
    return str(network)
    
# utilisation de la commande Nmap pour récupérer les adresse ip de tout les équipements présent dans le réseau

def scan_and_save_ips(network, output_file = "liste_ip.txt"):
    print(f"Scan du réseau {network} en cours...")


    try: 
        result = subprocess.run(["nmap","-sn",network],capture_output=True,text=True)

        if result.returncode != 0:
            print("Erreur d'exécution de Nmap")
            return

        hosts = []
        for line in result.stdout.splitlines(): #stdout est une chaîne de caractères (texte) qui contient la sortie complète de la commande exécutée(stocker dans result dans notre cas) (tout ce que le programme a affiché normalement dans le terminal). splitlines divise ce contenue en ligne
            if "Nmap scan report for" in line: # si une ligne contient le text entre côte
                ip = line.split()[-1].strip("()")        # on coupe la ligne en mot pour former une liste contenant une adresse ip comme dernier élement
                hosts.append(ip)               # Ajout des addresses ip pour former la liste
        
        with open(output_file,"w") as f:
            for ip in hosts:
                f.write(ip + "\n")
        
        print(f"{len(hosts)} adresses IP trouvées. Résultats enregistrés dans {output_file}.")

    except FileNotFoundError:
        print("Nmap n'est pas installer ou introuvable.")


