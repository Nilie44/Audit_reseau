import subprocess
import pandas as pd
import ipaddress
import time
from gvm.protocols.gmp import Gmp
from gvm.connections import UnixSocketConnection
from gvm.transforms import EtreeCheckCommandTransform
from concurrent.futures import ThreadPoolExecutor, as_completed
from lxml import etree

# ---- Configuration de OpenVAS ---
USERNAME = " "
PASSWORD = " "
FULL_AND_FAST_ID = " "
SCANNER_ID = " "
#PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"  # All IANA TCP and UDP

# Charger la liste d'IP depuis le fichier générer par nmap
def load_ip_list(file_path="liste_ip.txt"):
    valid_ips = []
    with open(file_path, "r") as f:
        for line in f:
            ip = line.strip().strip("()")
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                print(f"Adresse IP invalide ignorée : {ip}")
    return valid_ips

# Fonction principale de scan d'une IP
def scan_ip(ip, index):
    try:
        connection = UnixSocketConnection(path="/run/gvmd/gvmd.sock") #connexion au demon gvm via socket local
        transform = EtreeCheckCommandTransform() # sert a tronformer les fichier xml pour être utiliser en python

        with Gmp(connection, transform=transform) as gmp:
            # Authentification
            time.sleep(1)
            try:
                gmp.authenticate(USERNAME, PASSWORD)
                print(f"[{ip}] Authentification réussie")
            except Exception as e:
                return [{
                    "Host": ip, "Hostname": "", "Ports": "",
                    "Vulnerabilities": "", "Descriptions": "",
                    "Solutions": "", "CVEs": "", "Severity": "", "Threat": "",
                    "Erreur": f"Echec d'authentification: {str(e)}"
                }]

            # Vérifier si un target existe déjà
            existing_target_id = None
            for t in gmp.get_targets().xpath("target"):
                if t.findtext("hosts") == ip:
                    existing_target_id = t.get("id")
                    break

            # Créer le target si inexistant
            
            if existing_target_id: # si la cible existe, il sera reutiliser
                target_id = existing_target_id
                print(f"[{ip}] Target existant trouvé: {target_id}")
            else:
                try:
                    #création d'un nouveau target
                    new_target = gmp.create_target(
                        name=f"target-{ip}-{index}",
                        hosts=[ip],
                        port_list_id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
                    )
                    target_id = new_target.get("id")
                    print(f"[{ip}] Target créé: {target_id}")
                except Exception as e:
                    return [{
                        "Host": ip, "Hostname": "", "Ports": "",
                        "Vulnerabilities": "", "Descriptions": "",
                        "Solutions": "", "CVEs": "", "Severity": "", "Threat": "",
                        "Erreur": f"Erreur création target: {str(e)}"
                    }]

            # Créer la tâche de scan
            try:
                task = gmp.create_task(
                    name=f"task-{ip}-{index}",
                    config_id=FULL_AND_FAST_ID, #indique le type de scan utilisé
                    target_id=target_id,
                    scanner_id=SCANNER_ID
                )
            except Exception as e:
                return [{
                    "Host": ip, "Hostname": "", "Ports": "",
                    "Vulnerabilities": "", "Descriptions": "",
                    "Solutions": "", "CVEs": "", "Severity": "", "Threat": "",
                    "Erreur": f"Erreur création tâche: {str(e)}"
                }]

            task_id = task.get("id") # recuperation de l'id de la tache task qui viens d'être créer
            gmp.start_task(task_id)  #Demarrer le scan de la tache
            print(f"[{ip}] Scan démarré (task {task_id})")

            # Attendre la fin du scan
            max_wait = 90 * 60 # Si un scan faire plus de 90 minutes alors il est arrêter automatiquement
            ellapse = 0
            report_id = None

            while ellapse < max_wait:
                task_info = gmp.get_task(task_id)
                status = task_info.findtext("task/status")
                progress = task_info.findtext("task/progress") or "0"
                print(f"[{ip}] État : {status} - Progression : {progress}% - {ellapse//60} min")
                if status == "Done":
                    report_id = task_info.xpath("task/last_report/report/@id")[0] # recupère l'attribut id de la balise report.
                    break
                time.sleep(15)
                ellapse += 15

            if not report_id:
                return [{"Host": ip, "Erreur": "Timeout : scan trop long"}]

            # Récupération du rapport
            report = gmp.get_report(
                report_id=report_id,
                details=True,
                filter_string="levels=all", # Permets de récupérer toutes les vulnérabilités
                ignore_pagination=True
            )
            results = report.xpath("//result")

            """# Affichage d’un XML brut pour debug
            if results:
                print("\n--- XML brut pour debug ---")
                print(etree.tostring(results[0], pretty_print=True).decode())
            else:
                print(f"Aucun résultat pour {ip}")"""

            # Extraction des données
            lignes = []
            for r in results:
                reported_ip = ip
                port = r.findtext("port") or "" # la fonction findtext permet de chercher un sous element et de retourner directement son contenue

                # hostname
                hostname = ""
                host_tag = r.find("host") #la fonction find() permet de chercher le premier sous ens correspondant au chemin spécifié et retourne un objet xml.  le but est de pourvoir accéder au sous noeud complet pour lire
                if host_tag is not None:
                    hostname_elem = host_tag.find("hostname")
                    if hostname_elem is not None and hostname_elem.text:
                        hostname = hostname_elem.text.strip()

                # vuln info
                nvt = r.find("nvt")
                name = nvt.findtext("name") if nvt is not None else ""
                description = r.findtext("description") or ""

                # cves
                cve_list = []
                if nvt is not None:
                    refs = nvt.find("refs")
                    if refs is not None:
                        for ref in refs.findall("ref"): # cherche tous les elements enfants correspondant au chemin Xpath. et retourne une liste de balise XML
                            if ref is not None and ref.get("type") == "cve":
                                cve_id = ref.get("id")
                                if cve_id:
                                    cve_list.append(cve_id)

                # solution
                solution = ""
                if nvt is not None:
                    solution = nvt.findtext("solution") or ""

                severity = r.findtext("severity") or ""
                threat = r.findtext("threat") or ""

                lignes.append({
                    "Host": reported_ip,
                    "Hostname": hostname,
                    "Ports": port,
                    "Vulnerabilities": name,
                    "Descriptions": description.strip(),
                    "Solutions": solution.strip(),
                    "CVEs": ", ".join(cve_list),
                    "Severity": severity,
                    "Threat": threat
                })

            return lignes

    except Exception as e:
        return [{
            "Host": ip, "Hostname": "", "Ports": "",
            "Vulnerabilities": "", "Descriptions": "",
            "Solutions": "", "CVEs": "", "Severity": "",
            "Threat": "", "Erreur": str(e)
        }]

# Exécution du scan en parallèle
def run_scans(ip_list):
    all_results = []
    batch_size = 1  # Nombre de scan lancer simultanément, limiter pour éviter les conflits
    for i in range(0, len(ip_list), batch_size):
        batch = ip_list[i:i + batch_size] # on extrait un sous ensembles de 10 IPs a partir de la position i
        print(f"Scan du lot {i} à {i + len(batch) - 1}...")

        # Création d'un pool de threads pour lancer plusieurs scans en parallèle
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            futures = {executor.submit(scan_ip, ip, i + idx): ip for idx, ip in enumerate(batch)}  # Pour chaque IP du lot, on soumet la fonction scan_ip au thread pool
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if isinstance(result, list):   # Si la fonction scan_ip a bien renvoyé une liste, on ajoute tout à all_results
                        all_results.extend(result)
                except Exception as e:
                    all_results.append({
                        "Host": futures[future],
                        "Hostname": "", "Ports": "",
                        "Vulnerabilities": "", "Descriptions": "",
                        "Solutions": "", "CVEs": "",
                        "Severity": "", "Threat": "",
                        "Erreur": str(e)
                    })
    return all_results

# Export Excel
def save_to_excel(data, filename="rapport_vulnerabilites.xlsx"):
    df = pd.DataFrame(data)
    #df["Host"] = df["Host"].mask(df["Host"].eq(df["Host"].shift()))
    #df.to_excel(filename, index=False)
    print(f"[✔] Rapport Excel généré : {filename}")

def save_to_csv(data, filename="rapport_vulnerabilities.csv"):
    df = pd.DataFrame(data)
    #masquer les adresse IP et hostname répétées pour lisibilité. 
    #df["Host"] = df["Host"].mask(df["Host"].eq(df["Host"].shift()))
    #df["Hostname"] = df["Hostname"].mask(df["Hostname"].eq(df["Hostname"].shift()))
    #Enregistrement du fichier csv avec encodage UFT-8
    df.to_csv(filename, index=False, encoding="utf-8")
    print(f"Rapport CSV généré: {filename}")

