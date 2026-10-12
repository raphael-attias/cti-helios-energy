#!/usr/bin/env python3
"""Génère les règles Sigma du challenge (15) et leur registre. Exécuter avec le venv dédié :
   /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 07-Detection-Tests/generer-sigma.py

Statuts de fondement : DIRECTE (observation précise d'un artefact), IOC (valeurs d'IoC du dossier, non vérifiées), CHASSE (règle complémentaire,
NE prouve AUCUNE technique observée). Les chemins complets sont souvent absents des journaux du dossier : les motifs d'images n'utilisent
donc pas de séparateur de chemin initial quand la source n'en contient pas (limite documentée)."""
import csv, os, uuid, yaml

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "07-Detection-Tests", "sigma")
os.makedirs(OUT, exist_ok=True)
NS = uuid.UUID("5f1e3c3a-0d6b-4b3b-9d57-7a1e4c0f1e11")

R = []   # (det, fichier, fondement, artefacts, regle dict, backend_note)

def rule(det, slug, fondement, artefacts, title, desc, logsource, detection, level, fps, tags, refs, note=""):
    d = {"title": title, "id": str(uuid.uuid5(NS, det)), "status": "experimental", "description": desc + f" [{det} | fondement : {fondement} | artefacts : {', '.join(artefacts)}]",
         "references": refs, "author": "Équipe CTI (challenge fictif Helios)", "date": "2026-10-06", "tags": tags, "logsource": logsource, "detection": detection,
         "falsepositives": fps, "level": level}
    R.append((det, f"{det}-{slug}.yml", fondement, artefacts, d, note))

OFF = ["winword.exe", "excel.exe", "powerpnt.exe"]
rule("DET-001", "office-powershell-encode-masque", "DIRECTE", ["ALERT-001", "journal l.1"], "Office lançant PowerShell encodé et masqué",
     "Un processus Office engendre powershell.exe avec une commande encodée et une fenêtre masquée (observé : winword.exe -> powershell.exe -enc ... -w hidden).",
     {"category": "process_creation", "product": "windows"},
     {"parent": {"ParentImage|endswith": OFF}, "ps": {"Image|endswith": "powershell.exe"}, "enc": {"CommandLine|contains": ["-enc", "-encodedcommand"]},
      "hid": {"CommandLine|contains": ["-w hidden", "-windowstyle hidden"]}, "condition": "parent and ps and enc and hid"},
     "high", ["Macros légitimes d'automatisation ouvrant PowerShell (rare avec -enc ET fenêtre masquée)"], ["attack.execution", "attack.t1059.001", "attack.stealth", "attack.t1564.003"],
     ["alerte ALERT-001"])
rule("DET-002", "powershell-enc-iex-chasse", "CHASSE", ["ALERT-001"], "Chasse : PowerShell encodé dont le préfixe décodé est IEX",
     "Le préfixe base64 SQBFAFgA se décode (UTF-16LE) en IEX. Règle de CHASSE complémentaire : ne prouve aucune technique observée à elle seule.",
     {"category": "process_creation", "product": "windows"},
     {"ps": {"Image|endswith": "powershell.exe"}, "enc": {"CommandLine|contains|all": ["-enc", "SQBFAFgA"]}, "condition": "ps and enc"},
     "medium", ["Scripts d'administration encodés commençant par IEX"], ["attack.execution", "attack.t1059.001"], ["alerte ALERT-001"])
rule("DET-003", "proxy-telechargement-exe", "DIRECTE", ["ALERT-002", "journal l.2"], "Téléchargement d'un exécutable par GET avec réponse 200 via le proxy",
     "Observé : GET d'un .exe, réponse 200, 421376 octets. Règle large : exige une liste d'autorisation des domaines de mise à jour.",
     {"category": "proxy"}, {"sel": {"cs-method": "GET", "c-uri|endswith": ".exe", "sc-status": 200}, "condition": "sel"},
     "medium", ["Mises à jour logicielles légitimes", "Téléchargements d'outils d'administration"], ["attack.command-and-control", "attack.t1105"], ["alerte ALERT-002"])
rule("DET-004", "ioc-domaines-urls", "IOC", ["IOC-013..018", "IOC-029..032", "journal l.2, l.11"], "Requête proxy vers un domaine du dossier (IoC non vérifiés)",
     "Domaines en .test du dossier pédagogique (non résolvables). Règle IOC : à retirer après l'exercice ; ne démontre pas un comportement.",
     {"category": "proxy"}, {"sel": {"c-uri|contains": ["cdn-svc-update.test", "api-telemetry-eu.test", "mail-secure-login.test", "static-assets-cache.test", "helios-energy-portal.test", "update-win-msft.test"]}, "condition": "sel"},
     "medium", ["Aucun hors exercice (domaines fictifs)"], ["attack.command-and-control"], ["IOC-013 à 018"])
rule("DET-005", "schtasks-edge-lookalike", "DIRECTE", ["ALERT-003", "journal l.3"], "Création de tâche planifiée imitant la mise à jour Edge",
     "Observé : création de MicrosoftEdgeUpdateTaskMachine (la commande schtasks n'est visible que dans le détail de l'alerte).",
     {"category": "process_creation", "product": "windows"},
     {"sel": {"Image|endswith": "schtasks.exe", "CommandLine|contains|all": ["/create", "MicrosoftEdgeUpdateTaskMachine"]}, "legit": {"ParentImage|endswith": "MicrosoftEdgeUpdate.exe"}, "condition": "sel and not legit"},
     "medium", ["Installation légitime de Microsoft Edge (parent MicrosoftEdgeUpdate.exe, exclu)", "Noms réels de tâches Edge à vérifier sur un poste de référence"], ["attack.persistence", "attack.t1053.005"], ["alerte ALERT-003"])
rule("DET-006", "ioc-ip-destinations", "IOC", ["IOC-020", "IOC-021", "IOC-022", "IOC-024", "journal l.4, l.10"], "Connexion vers une IP du dossier (IoC non vérifiés)",
     "IP en plages de documentation RFC 5737. Règle IOC. Ne démontre pas un balisage ni une exfiltration.",
     {"product": "zeek", "service": "conn"}, {"sel": {"id.resp_h": ["198.51.100.24", "203.0.113.14", "203.0.113.15", "203.0.113.28"]}, "condition": "sel"},
     "medium", ["Aucun hors exercice (plages de documentation)"], ["attack.command-and-control"], ["IOC-020, 021, 022, 024"])
rule("DET-007", "acces-lsass-0x1010", "DIRECTE", ["ALERT-005", "journal l.8"], "Accès à LSASS avec droits de lecture mémoire (0x1010)",
     "Observé : target=lsass.exe granted=0x1010 par rundll32_helper.dll. Le masque 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ.",
     {"category": "process_access", "product": "windows"},
     {"sel": {"TargetImage|endswith": "lsass.exe", "GrantedAccess": ["0x1010", "0x1410"]}, "legit": {"SourceImage|startswith": ["C:\\Windows\\System32\\", "C:\\Program Files\\Windows Defender\\"]}, "condition": "sel and not legit"},
     "high", ["Outils de sécurité, EDR, antivirus lisant LSASS (à placer dans la liste d'exclusion)"], ["attack.credential-access", "attack.t1003.001"], ["alerte ALERT-005"])
rule("DET-008", "zeek-balayage-445-3389", "DIRECTE", ["ALERT-006", "journal l.5"], "Balayage détecté par Zeek sur SMB et RDP",
     "Observé : scan detected 198.51.100.55 -> 10.20.0.0/16 dports=445,3389. La nature de l'IP source est inconnue (I-05).",
     {"product": "zeek", "service": "notice"}, {"sel": {"msg|contains": "scan detected"}, "ports": {"msg|contains": ["dports=445", "3389"]}, "condition": "sel and ports"},
     "medium", ["Scanners de vulnérabilités internes autorisés"], ["attack.discovery", "attack.t1046"], ["alerte ALERT-006"])
rule("DET-009", "rdp-compte-service", "DIRECTE", ["ALERT-007", "journal l.6"], "Connexion RDP (type 10) d'un compte de service",
     "Observé : 4624 type 10 pour svc-backup-temp. Chronologie du compte contradictoire (I-03).",
     {"product": "windows", "service": "security"}, {"sel": {"EventID": 4624, "LogonType": 10, "TargetUserName|startswith": "svc-"}, "condition": "sel"},
     "medium", ["Comptes de service d'administration utilisant RDP légitimement"], ["attack.lateral-movement", "attack.t1021.001", "attack.t1078"], ["alerte ALERT-007"])
rule("DET-010", "remote-thread-explorer", "DIRECTE", ["ALERT-008", "journal l.7"], "Thread distant créé dans explorer.exe",
     "Observé : CreateRemoteThread into explorer.exe RWX region. Détecte une injection (T1055 parent) ; ne démontre pas le Process Hollowing.",
     {"category": "create_remote_thread", "product": "windows"},
     {"sel": {"TargetImage|endswith": "explorer.exe"}, "legit": {"SourceImage|startswith": "C:\\Windows\\System32\\"}, "condition": "sel and not legit"},
     "high", ["Logiciels d'accessibilité ou d'automatisation injectant dans le shell"], ["attack.stealth", "attack.privilege-escalation", "attack.t1055"], ["alerte ALERT-008"])
rule("DET-011", "creation-compte-temp", "DIRECTE", ["ALERT-009", "journal l.9"], "Création d'un compte dont le nom finit par -temp",
     "Observé : 4720 pour svc-backup-temp sur dc-01. Qualification T1136.002 probable (compte de domaine à confirmer).",
     {"product": "windows", "service": "security"}, {"sel": {"EventID": 4720, "TargetUserName|endswith": "-temp"}, "condition": "sel"},
     "medium", ["Comptes temporaires légitimes suivant la même convention de nommage"], ["attack.persistence", "attack.t1136.002"], ["alerte ALERT-009"])
rule("DET-012", "sortie-volumineuse-claire", "DIRECTE", ["ALERT-010", "journal l.10"], "Sortie réseau supérieure à 1 Go",
     "Observé : 2 469 135 790 octets vers 203.0.113.28:8080. Le champ du journal est « bytes » (direction non précisée) : orig_bytes est supposé.",
     {"product": "zeek", "service": "conn"}, {"sel": {"orig_bytes|gte": 1000000000}, "condition": "sel"},
     "high", ["Sauvegardes et synchronisations légitimes vers l'extérieur"], ["attack.exfiltration", "attack.t1048.003"], ["alerte ALERT-010"])
rule("DET-013", "journal-security-efface-1102", "DIRECTE", ["ALERT-012", "journal l.12"], "Effacement du journal Security (1102)",
     "Observé : 1102 audit log cleared sur comptabilite-07.", {"product": "windows", "service": "security"}, {"sel": {"EventID": 1102}, "condition": "sel"},
     "high", ["Maintenance planifiée des journaux"], ["attack.defense-impairment", "attack.t1685.005"], ["alerte ALERT-012"])
rule("DET-014", "wevtutil-cl-security", "DIRECTE", ["ALERT-012", "journal l.12"], "Commande wevtutil cl Security",
     "Observé : wevtutil cl Security.", {"category": "process_creation", "product": "windows"},
     {"sel": {"Image|endswith": "wevtutil.exe", "CommandLine|contains|all": ["cl", "security"]}, "condition": "sel"},
     "high", ["Maintenance planifiée des journaux"], ["attack.defense-impairment", "attack.t1685.005"], ["alerte ALERT-012"])
rule("DET-015", "ioc-noms-de-fichiers", "IOC", ["BIN-001", "BIN-002", "BIN-003"], "Processus portant un nom de fichier du dossier (fiches binaires)",
     "Noms issus des fiches (échantillons non fournis). Règle IOC : n'établit ni capacité ni comportement.",
     {"category": "process_creation", "product": "windows"}, {"sel": {"Image|endswith": ["svchost_update.exe", "rundll32_helper.dll"]}, "condition": "sel"},
     "medium", ["Aucun hors exercice"], ["attack.execution"], ["fiches BIN-02 et BIN-03"])

reg = []
for det, fn, fond, arts, d, note in R:
    with open(os.path.join(OUT, fn), "w", encoding="utf-8") as f:
        yaml.safe_dump(d, f, allow_unicode=True, sort_keys=False, width=140)
    reg.append([det, fn, d["id"], d["title"], fond, " ; ".join(arts), yaml.safe_dump(d["logsource"], default_flow_style=True).strip(), d["level"],
                ", ".join(t for t in d["tags"] if t.startswith("attack.t")), " | ".join(d["falsepositives"])])
with open(os.path.join(BASE, "07-Detection-Tests", "Registre-regles.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["det", "fichier", "sigma_id", "titre", "fondement", "artefacts", "logsource", "niveau", "attack", "faux_positifs_plausibles"])
    w.writerows(reg)
print(len(R), "règles écrites dans", OUT)
