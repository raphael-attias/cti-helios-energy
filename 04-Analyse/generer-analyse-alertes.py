#!/usr/bin/env python3
"""Génère la matrice d'analyse des 12 alertes, la chronologie provisoire et la matrice ATT&CK (alertes).

Lecture seule sur fourniture/. Aucune connexion réseau. Bibliothèque standard.
CONTRÔLE INTÉGRÉ : chaque preuve citée (fichier, ligne, extrait) est relue dans la source ;
le script échoue si un extrait n'existe pas à la ligne indiquée.
Les originaux ne sont jamais corrigés : les interprétations alternatives sont documentées, pas appliquées.
"""
import csv, json, os, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "fourniture")
OUT = os.path.join(BASE, "04-Analyse")
F_AL, F_LOG, F_IOC, F_FICHE, F_MEMO = ("03_alertes_siem_12.csv", "05_journaux_bruts.log", "02_indicateurs_40.csv",
                                        "01_fiches_analyse_binaires.md", "04_memo_technique_SOC.md")
cache = {}


def lines(f):
    if f not in cache:
        cache[f] = open(os.path.join(SRC, f), encoding="utf-8").read().splitlines()
    return cache[f]


def line(f, n):
    return lines(f)[n - 1]


errors = []


def check(f, n, sub):
    if sub not in line(f, n):
        errors.append(f"PREUVE INTROUVABLE {f}:{n} : {sub!r}")


# --------------------------------------------------------------------------- ATT&CK
ATT = {  # id: (nom officiel, version page, dernière modif affichée, statut de vérification)
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "1.5", "12 May 2026", "VERIFIE"),
    "T1564.003": ("Hide Artifacts: Hidden Window", "2.0", "12 May 2026", "VERIFIE"),
    "T1105": ("Ingress Tool Transfer", "2.6", "12 May 2026", "VERIFIE"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "1.8", "12 May 2026", "VERIFIE"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "1.5", "12 May 2026", "VERIFIE"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "1.5", "12 May 2026", "VERIFIE"),
    "T1046": ("Network Service Discovery", "3.2", "12 May 2026", "VERIFIE"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "1.4", "12 May 2026", "VERIFIE"),
    "T1078": ("Valid Accounts", "3.0", "12 May 2026", "VERIFIE (T1078.002 Domain Accounts listée comme sous-technique)"),
    "T1055": ("Process Injection", "2.0", "12 May 2026", "VERIFIE (12 sous-techniques listées)"),
    "T1055.001": ("Process Injection: Dynamic-link Library Injection", "2.0", "12 May 2026", "VERIFIE"),
    "T1055.002": ("Process Injection: Portable Executable Injection", "2.0", "12 May 2026", "VERIFIE"),
    "T1055.012": ("Process Injection: Process Hollowing", "2.0", "12 May 2026", "VERIFIE"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "1.6", "12 May 2026", "VERIFIE"),
    "T1136.002": ("Create Account: Domain Account", "1.1", "24 October 2025", "VERIFIE (la page cite l'événement 4720)"),
    "T1048.003": ("Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol", "2.2", "12 May 2026", "VERIFIE"),
    "T1008": ("Fallback Channels", "1.1", "12 May 2026", "VERIFIE"),
    "T1685.005": ("Disable or Modify Tools: Clear Windows Event Logs", "ATT&CK v19", "12 May 2026", "VERIFIE sur attack.mitre.org (tactique Defense Impairment TA0112) ; ancien identifiant T1070.001 (Indicator Removal, v10 à v14 vérifiées) ABSENT des sous-techniques courantes de T1070 : identifiant hérité, à ne plus utiliser comme référence courante"),
}

# --------------------------------------------------------------------------- ANALYSE
# preuves : liste de (fichier, ligne, extrait) ; log_line = ligne du journal brut correspondant (tri chronologique)
A = {}

A[1] = dict(
    log=1, compte="INCONNU (non indiqué dans la ligne de journal)",
    iocs="IOC-040 (hôte) ; IOC-001/002/003 (BIN-001, relation DECLAREE par la fiche, pas observée) ; IOC-010 (charge PowerShell déchiffrée, 08:32)",
    suspect="Word est le processus parent d'un powershell.exe lancé avec une commande encodée (-enc) et une fenêtre masquée (-w hidden). Enchaînement fréquemment associé à l'exécution de macros, mais non concluant seul.",
    conclusion=("OBSERVE : powershell.exe est un processus enfant de winword.exe avec -enc et -w hidden. Le préfixe base64 « SQBFAFgA » se décode (UTF-16LE) en « IEX » (Invoke-Expression) : "
                "décodage reproduit par nous ; le reste de la commande est tronqué (« ... ») donc la charge réelle est INCONNUE. Que ce soit une macro VBA, un courriel ou BIN-001 n'est pas dans la ligne : "
                "c'est déclaré par la fiche BIN-01 et le mémo. NOUVELLE CONTRADICTION : BIN-01 est un classeur .xlsm (Excel) mais le parent est winword.exe (Word)."),
    techniques=[("T1059.001", "observée", "powershell.exe lancé, argument -enc"), ("T1564.003", "observée", "argument -w hidden (fenêtre masquée) dans la même ligne"),
                ("T1566.001 / T1204.002 / T1059.005", "non démontrée", "déclarées par la fiche BIN-01 seulement ; ni courriel ni ouverture de fichier ni code VBA dans les journaux fournis")],
    preuves=[(F_LOG, 1, "winword.exe -> powershell.exe -enc SQBFAFgA... -w hidden"), (F_AL, 2, "winword.exe engendre powershell.exe -enc <base64> -w hidden")],
    qualif="OBSERVE (exécution) ; caractère malveillant : CORROBORE par ALERT-002 et la fiche (non indépendants entre eux)", confiance="élevée pour T1059.001 ; moyenne pour la malveillance prise isolément",
    contradictions="I-18 (parent winword.exe vs classeur .xlsm) ; première vue de BIN-01 08:30 vs événement 08:31 (1 min, cohérent)",
    liens="ALERT-002 (+11 min), ALERT-003 (+15 min), ALERT-004 (+45 min) : même hôte, séquence temporelle compatible avec un téléchargement puis une persistance (lien TEMPOREL, pas causal prouvé)",
    verifs="Ligne de commande complète (Sysmon EID 1, CommandLine non tronquée) ; processus parent réel (winword vs excel) ; journaux PowerShell (script block) ; courriel et pièce jointe sur la passerelle de messagerie ; compte exécutant.",
)
A[2] = dict(
    log=2, compte="INCONNU (le journal Squid ne porte pas d'utilisateur)",
    iocs="IOC-013 (domaine), IOC-029 (URL), IOC-019 (IP, résolution déclarée par le SOC), IOC-004/005/006 (BIN-002), IOC-040",
    suspect="Téléchargement d'un exécutable nommé comme un composant système (svchost_update.exe) depuis un domaine que l'alerte dit « jamais vu ». Le caractère « jamais vu » n'est pas vérifiable : aucun historique de domaine n'est fourni.",
    conclusion=("OBSERVE : requête GET vers l'URL de l'exécutable, réponse 200, 421376 octets. CORROBORE : 421376 est exactement la taille déclarée de BIN-002 (fiche BIN-02) ; deux artefacts du même fournisseur, donc pas indépendants. "
                "NON DEMONTRE : que le fichier soit un PE (le journal ne dit rien du contenu), qu'il ait été exécuté, que le client soit powershell.exe (pas d'user-agent). "
                "Remarque technique : l'URL complète d'un flux HTTPS visible dans Squid suppose une interception TLS du proxy (HYP-010, non confirmée : limite)."),
    techniques=[("T1105", "observée", "transfert HTTP 200 d'un exécutable depuis une URL externe")],
    preuves=[(F_LOG, 2, "GET https://cdn-svc-update.test/win/svchost_update.exe 200 421376"), (F_FICHE, 42, "421376"), (F_AL, 3, "svchost_update.exe")],
    qualif="OBSERVE (transfert) + CORROBORE (taille)", confiance="élevée pour le transfert ; faible pour le contenu et l'exécution",
    contradictions="Aucune majeure. La résolution domaine vers 198.51.100.23 (IOC-019) est déclarée, non observée dans les journaux.",
    liens="ALERT-001 (11 min avant ; lien causal PowerShell vers téléchargement PLAUSIBLE, non prouvé) ; ALERT-003 (+4 min)",
    verifs="User-agent et processus client ; journal DNS ; interception TLS du proxy ; copie en cache du fichier et son hash (comparaison à IOC-004) ; historique du domaine (requête tierce soumise à accord).",
)
A[3] = dict(
    log=3, compte="INCONNU",
    iocs="IOC-036 (nom de tâche), IOC-038 (clé Run, 08:44, sans alerte associée), IOC-004/005/006 (BIN-002, lien déclaré par la fiche)",
    suspect="Création d'une tâche planifiée dont le nom imite une mise à jour Microsoft Edge, 4 minutes après le téléchargement d'un exécutable.",
    conclusion=("OBSERVE : une tâche nommée MicrosoftEdgeUpdateTaskMachine est créée sur comptabilite-07 (ligne de journal). La commande schtasks /create ne figure que dans le détail de l'alerte, pas dans le journal brut. "
                "INCONNU : programme exécuté par la tâche, compte, planification ; donc l'usage comme persistance et le lien avec BIN-002 (déclaré par la fiche BIN-02) ne sont pas démontrés par cet événement. "
                "Réserve de format : le libellé « Sysmon: Scheduled Task Created » ne correspond pas, à ma connaissance, à un événement Sysmon standard (la création de tâche se voit plutôt dans Security 4698) : origine réelle du journal inconnue (I-20, limite)."),
    techniques=[("T1053.005", "observée", "création d'une tâche planifiée")],
    preuves=[(F_LOG, 3, "Scheduled Task Created: MicrosoftEdgeUpdateTaskMachine"), (F_AL, 4, "schtasks /create /tn MicrosoftEdgeUpdateTaskMachine")],
    qualif="OBSERVE (création) ; persistance : HYPOTHESE", confiance="élevée pour la création ; moyenne pour l'objectif malveillant",
    contradictions="I-20 (commande dans l'alerte mais pas dans le journal ; libellé non standard). Deux mécanismes de persistance distincts (clé Run à 08:44, tâche à 08:46) sans alerte pour le premier.",
    liens="ALERT-002 (4 min avant), ALERT-004 (+30 min)",
    verifs="Security 4698 (XML de la tâche : action, utilisateur, déclencheur) ; comparaison avec les vraies tâches Edge sur un poste de référence ; valeur de la clé Run (IOC-038, valeur tronquée à « ... » dans la source).",
)
A[4] = dict(
    log=4, compte="INCONNU",
    iocs="IOC-020 (198.51.100.24, résolution déclarée de api-telemetry-eu.test), IOC-014 (domaine), IOC-031 (URL de balise), IOC-021/022 (serveurs de commande déclarés), IOC-033 (certificat partagé déclaré)",
    suspect="Connexion sortante courte (0,4 s, 812 octets) étiquetée « beacon » par la source vers une IP en 443, 30 minutes après l'exécution initiale.",
    conclusion=("OBSERVE : UNE seule connexion vers 198.51.100.24:443 (durée 0,4 s, 812 octets émis). NON DEMONTRE : la périodicité « ~300 s » (une seule ligne ; l'intervalle vient du texte de l'alerte et de la fiche BIN-02, c'est-à-dire de déclarations). "
                "L'étiquette « (beacon) » est celle de la source, pas une mesure. Le protocole applicatif n'est pas visible dans un journal de connexion Zeek : T1071.001 repose sur le port 443 et sur la fiche. "
                "Le lien domaine vers IP est déclaré (IOC-020), le journal ne montre que l'IP."),
    techniques=[("T1071.001", "probable", "connexion sortante en 443 (protocole applicatif non visible) ; chiffrement T1573 : déclaré par la fiche seulement")],
    preuves=[(F_LOG, 4, "conn 198.51.100.24:443 duration=0.4 orig_bytes=812 (beacon)"), (F_AL, 5, "toutes les ~300 s")],
    qualif="OBSERVE (1 connexion) ; balisage : HYPOTHESE FORTE non démontrée", confiance="moyenne",
    contradictions="I-12 (deux « C2 » distincts : 198.51.100.24 vu ici, 203.0.113.14 « principal » dans IOC-021). IOC-014 vu à 09:15, alerte et journal à 09:16 (1 min).",
    liens="ALERT-001/002/003 (même hôte, 30 à 45 min plus tard) ; ALERT-011 (repli du canal, 3 jours plus tard)",
    verifs="Série complète des connexions Zeek vers cette IP depuis 08:41 (intervalle moyen, gigue de 20 % annoncée) ; ssl.log (SNI, certificat CN=update-service, JA3) ; DNS ; lien IOC-020.",
)
A[5] = dict(
    log=8, compte="INCONNU (le journal ne nomme ni le compte ni le processus ; l'image source est « rundll32_helper.dll »)",
    iocs="IOC-007/008/009 (BIN-003), IOC-012, IOC-039 (fichier de collecte), IOC-037 (compte créé 5 min plus tard)",
    suspect="Accès au processus LSASS d'un contrôleur de domaine par une image sans doute chargée via rundll32, 2 minutes après la première apparition de BIN-003.",
    conclusion=("OBSERVE : accès à lsass.exe avec le masque 0x1010, soit PROCESS_QUERY_LIMITED_INFORMATION (0x1000) + PROCESS_VM_READ (0x0010) : droits de lecture de la mémoire, compatibles avec une extraction d'identifiants. "
                "Ce masque n'est pas un indicateur suffisant seul (des outils de sécurité légitimes peuvent lire LSASS) ; la page ATT&CK T1003.001 cite d'ailleurs un autre masque (0x1F0FFF) comme exemple. "
                "NON DEMONTRE : qu'un identifiant ait été extrait ou réutilisé. « Non signé » (alerte) n'est pas dans la ligne de journal. "
                "INCONNU : comment l'attaquant est arrivé sur dc-01 (aucun mécanisme de mouvement latéral n'est fourni)."),
    techniques=[("T1003.001", "probable", "accès mémoire à lsass.exe observé (0x1010) ; extraction effective non démontrée")],
    preuves=[(F_LOG, 8, "target=lsass.exe granted=0x1010 by rundll32_helper.dll"), (F_AL, 6, "non signé")],
    qualif="OBSERVE (accès) ; vol d'identifiants : HYPOTHESE FORTE", confiance="élevée pour l'accès ; moyenne pour l'extraction",
    contradictions="I-08 (une DLL n'est pas un processus) ; I-01 (alerte 5 hors séquence) ; « non signé » absent du journal (I-21)",
    liens="ALERT-009 (+5 min, compte créé : lien TEMPOREL, non causal), ALERT-010 (+1 h 24), ALERT-007 (compte utilisé 36 h AVANT : voir HYP-001)",
    verifs="Sysmon EID 10 complet (SourceImage, CallTrace, GrantedAccess, session) ; processus réel et signature ; événements d'ouverture de session et de privilèges (4672, 4648) ; EDR ; échantillon BIN-003 (non fourni).",
)
A[6] = dict(
    log=5, compte="Non applicable (événement réseau)",
    iocs="IOC-025 (198.51.100.55), IOC-026 (203.0.113.44, RDP), hôte émetteur du journal : comptabilite-07",
    suspect="Détection Zeek d'un balayage d'un /16 interne sur SMB (445) et RDP (3389), préparatoire à un déplacement latéral dans l'hypothèse d'un attaquant.",
    conclusion=("OBSERVE : Zeek signale un balayage de la source 198.51.100.55 vers 10.20.0.0/16 sur les ports 445 et 3389 ; le nombre de cibles et de paquets n'est pas fourni. "
                "Le journal est émis par comptabilite-07 mais ne dit pas que comptabilite-07 EST la source. L'IP source est dans une plage de documentation, pas RFC 1918, alors que la cible est interne : "
                "INCONNU. Interprétations (HYP-003, HYP-004) : (a) pseudonymisation de l'IP interne du poste, alors IOC-025 serait un actif victime et ne devrait PAS devenir un blocage ni un IoC offensif ; "
                "(b) scanneur externe atteignant le /16, alors vecteur d'entrée alternatif et IOC-025 est de l'infrastructure attaquante ; (c) erreur de donnée. "
                "Impact : choix (a) ou (b) change la chronologie, la liste d'IoC, les règles de détection et le périmètre de confinement."),
    techniques=[("T1046", "observée", "balayage de ports détecté sur 445 et 3389")],
    preuves=[(F_LOG, 5, "scan detected 198.51.100.55 -> 10.20.0.0/16 dports=445,3389"), (F_AL, 7, "scanne le sous-réseau 10.20.0.0/16")],
    qualif="OBSERVE (balayage) ; origine : INCONNU", confiance="élevée pour T1046 ; faible pour l'attribution à comptabilite-07 ou à un tiers",
    contradictions="I-05 (IP publique source d'un balayage interne) ; IOC-025 « depuis poste compromis » non étayé ; I-01 (ordre des alertes)",
    liens="ALERT-007 (RDP 15 h 35 plus tard : port 3389 balayé puis RDP observé, lien TEMPOREL) ; ALERT-004 (même hôte)",
    verifs="IP interne réelle de comptabilite-07 (DHCP, CMDB) ; détail Zeek (notice.log, nombre de destinations) ; règles NAT et pare-feu entre zones ; topologie du site.",
)
A[7] = dict(
    log=6, compte="svc-backup-temp (selon la ligne de journal)",
    iocs="IOC-026 (203.0.113.44, « RDP entrante », 01:47), IOC-037 (svc-backup-temp), hôte cible : srv-fichiers-02",
    suspect="Session RDP de nuit sur un serveur de fichiers par un compte de service au nom « temp ». Heure locale du site INCONNUE : la qualité « hors horaires » est supposée.",
    conclusion=("OBSERVE : événement 4624 de type 10 (ouverture de session interactive à distance, soit RDP : type 10 = RemoteInteractive selon la documentation Microsoft, non revérifié le 2026-10-07) pour svc-backup-temp sur srv-fichiers-02 ; heure interne 01:47. "
                "La source réseau est ABSENTE du journal : l'alerte dit « interne inhabituelle », IOC-026 dit une IP externe : INCONNU (I-04). "
                "CONTRADICTION MAJEURE : ce compte est créé par 4720 le 2026-03-05 à 14:12, soit environ 36 h APRES cette session (I-03). Impact des lectures : "
                "(HYP-001) compte préexistant recréé : alors le premier accès par ce compte précède le vol LSASS et l'origine des identifiants est à rechercher ailleurs ; "
                "(HYP-002) horloges ou fuseaux décalés : la chronologie entière est à reconsidérer ; (HYP-012) donnée mal alignée : l'événement ne peut pas servir de preuve."),
    techniques=[("T1021.001", "observée", "4624 type 10 = connexion à distance interactive"), ("T1078 (T1078.002 si compte de domaine)", "probable", "usage d'un compte valide ; domaine ou local non indiqué")],
    preuves=[(F_LOG, 6, "4624 Logon type=10 RDP account=svc-backup-temp time=01:47"), (F_AL, 8, "source interne inhabituelle"), (F_LOG, 9, "4720 User created svc-backup-temp")],
    qualif="OBSERVE (événement) ; fiabilité de l'événement : CONTESTEE", confiance="moyenne pour T1021.001 ; faible pour toute conclusion sur le compte",
    contradictions="I-03 (compte utilisé avant sa création) ; I-04 (source interne vs externe) ; 4624 « time=01:47 » vs horodatage 01:48Z (1 min)",
    liens="ALERT-009 (même compte, création 36 h plus tard), ALERT-006 (balayage 3389), ALERT-008 (+9 h 17, même hôte), ALERT-005",
    verifs="IpAddress et WorkstationName du 4624 ; whenCreated du compte dans l'annuaire ; historique 4720/4726 complet ; NTP et fuseaux de srv-fichiers-02 et dc-01 ; authentifications Kerberos (4768/4769).",
)
A[8] = dict(
    log=7, compte="INCONNU (ni compte ni image source dans la ligne)",
    iocs="IOC-011 (module injecté, sha256 8772b487..., 11:06, déclaré « par BIN-02 » par le SOC), IOC-004/005/006 (BIN-002, lien DECLARE), IOC-018 (domaine vu 11:04)",
    suspect="Création d'un thread dans explorer.exe avec une région mémoire exécutable en écriture (RWX) : signal classique d'injection de code dans un processus légitime.",
    conclusion=("LIBELLE ORIGINAL : « Injection de code dans un processus légitime », technique du SIEM T1055.012, sévérité Haute, détail « explorer.exe présente une région mémoire exécutable anormale ». "
                "LIGNE EXACTE : « 2026-03-04T11:05:00Z srv-fichiers-02 Sysmon: CreateRemoteThread into explorer.exe RWX region » (journal brut ligne 7). "
                "POURQUOI JE CONTESTE T1055.012 : selon la page ATT&CK (lue le 2026-10-06), le Process Hollowing consiste à créer un NOUVEAU processus suspendu puis à vider et remplacer sa mémoire ; il ne cible pas un processus déjà en cours. "
                "La ligne décrit un thread distant créé DANS explorer.exe (processus a priori déjà en cours) : rien ne montre la création suspendue ni le remplacement de mémoire. ATT&CK présente CreateRemoteThread comme moyen d'exécution de T1055.001 (DLL) et T1055.002 (PE). "
                "CE QUE L'ARTEFACT PERMET DE CONCLURE : sur srv-fichiers-02, le 2026-03-04 à 11:05Z, un thread distant a été créé dans explorer.exe, avec une région RWX : indice d'injection de code (T1055 au niveau parent). "
                "Une région RWX évoque du code écrit dans le processus (hypothèse faible sur PE ou code injecté plutôt que simple chargement de DLL : HYP-006). "
                "NON DEMONTRE : le Process Hollowing ; l'initiateur (SourceImage absent) ; que l'initiateur soit BIN-002 (seul IOC-011, déclaré par le SOC, le suggère) ; la nature du code ; son effet ; la présence de BIN-002 sur ce serveur ; le mécanisme d'arrivée sur ce serveur. "
                "NOTE : la fiche BIN-02 parle elle aussi de « creux de processus » dans explorer.exe, ce qui est interne ambigu (hollowing ne vise pas un processus existant) : à lever avec l'analyse de l'échantillon, non fourni. "
                "Le champ « RWX region » n'est pas, à ma connaissance, un champ standard d'un événement Sysmon 8 : la ligne semble résumée ou enrichie (à vérifier)."),
    techniques=[("T1055", "observée (indice)", "CreateRemoteThread into explorer.exe, région RWX"), ("T1055.001 / T1055.002", "non démontrée", "CreateRemoteThread est cité par ATT&CK pour ces sous-techniques ; la ligne ne les départage pas"),
                ("T1055.012", "contestée / non démontrée", "aucun processus suspendu ni remplacement de mémoire dans l'artefact")],
    preuves=[(F_LOG, 7, "CreateRemoteThread into explorer.exe RWX region"), (F_AL, 9, "T1055.012"), (F_AL, 9, "région mémoire exécutable anormale"), (F_FICHE, 49, "creux de processus")],
    qualif="OBSERVE (thread distant, RWX) ; sous-technique et initiateur : INCONNU", confiance="élevée pour « injection par thread distant » ; faible pour toute sous-technique ; très faible pour l'attribution à BIN-002",
    contradictions="I-06 (T1055.012 vs CreateRemoteThread) ; I-07 (BIN-002 récupéré sur comptabilite-07, injection sur srv-fichiers-02) ; fiche BIN-02 elle-même ambiguë",
    liens="ALERT-007 (même hôte, 9 h 17 plus tôt) ; ALERT-011 (même hôte, +16 h) ; lien avec ALERT-004 (C2) seulement par l'hypothèse BIN-002 présent sur srv-fichiers-02 (HYP-005)",
    verifs="Sysmon EID 8 complet (SourceImage, TargetImage, StartAddress, StartModule) et EID 10 ; arbre de processus ; image mémoire d'explorer.exe ; hash du module IOC-011 et son rapprochement avec BIN-002 ; recherche d'un événement de création de processus suspendu (test de T1055.012).",
)
A[9] = dict(
    log=9, compte="svc-backup-temp (compte créé ; SubjectUserName du créateur INCONNU)",
    iocs="IOC-037 (compte), IOC-007/008/009 (BIN-003, fiche : service créé à la volée, non vérifié), hôte dc-01",
    suspect="Compte au nom « svc-backup-temp » créé sur un contrôleur de domaine 5 minutes après un accès à LSASS, supprimé environ 45 minutes plus tard.",
    conclusion=("OBSERVE (selon une ligne qui condense deux événements) : 4720 (création d'utilisateur) et 4726 (suppression) pour svc-backup-temp, la seconde « 45m later » : l'heure du 4726 n'est pas fournie, elle est calculée. "
                "CONTESTATION DE T1543.003 : cette technique concerne la création ou modification de SERVICES Windows (page ATT&CK), pas un compte. Un événement 4720 est la création d'un compte ; la page ATT&CK de T1136.002 (Domain Account) cite justement 4720. "
                "Un compte créé sur un contrôleur de domaine est très probablement un compte de domaine (HYP-009 : le SIEM confond compte de service et service Windows). "
                "La fiche BIN-03 mentionne un « service Windows créé puis supprimé » : aucun événement de service (7045, 4697) n'est fourni, donc T1543.003 est NON DEMONTRE. "
                "Écarts : alerte 14:12, détail « créé à 14:10 » (aussi IOC-037), suppression « 14:55 » (détail) ou 14:57 (calcul)."),
    techniques=[("T1136.002", "probable", "4720 sur dc-01 ; nature domaine non établie"), ("T1543.003", "non démontrée", "aucun événement de service ; mapping SIEM suspect")],
    preuves=[(F_LOG, 9, "4720 User created svc-backup-temp / 4726 deleted 45m later"), (F_AL, 10, "créé à 14:10, supprimé à 14:55"), (F_AL, 10, "T1543.003")],
    qualif="OBSERVE (création/suppression de compte) ; objectif : HYPOTHESE", confiance="moyenne",
    contradictions="I-03 (compte utilisé 36 h avant) ; I-09 (14:10/14:12, 14:55/14:57) ; mapping SIEM T1543.003 incohérent avec 4720",
    liens="ALERT-007 (même compte), ALERT-005 (-5 min), ALERT-010 (+3 h 19)",
    verifs="Événement 4720 complet (créateur, SID, UPN) ; 4728/4732/4756 (groupes) ; 4726 avec son heure réelle ; whenCreated ; 7045/4697 sur dc-01 ; journal Directory Service.",
)
A[10] = dict(
    log=10, compte="INCONNU",
    iocs="IOC-024 (203.0.113.28 exfiltration), IOC-012 (archive chiffrée, 14:45), IOC-039 (fichier ~df3a9.tmp, 14:40), IOC-007/008/009 (BIN-003)",
    suspect="Volume sortant de plusieurs gigaoctets depuis un contrôleur de domaine vers une IP externe sur 8080, étiqueté « cleartext » par la source, 46 minutes après la préparation d'un fichier d'archive.",
    conclusion=("OBSERVE : sortie de 2 469 135 790 octets vers 203.0.113.28:8080 depuis dc-01 (2,47 Go décimal ou 2,30 Gio ; l'alerte dit « 2,3 Go » sans préciser l'unité : I-10). "
                "NON DEMONTRE : le contenu, le lien avec l'archive (IOC-012/039 : lien TEMPOREL 14:40 à 15:31, déclaré par la fiche BIN-03 et IOC-024), la direction exacte du champ « bytes= », le protocole applicatif. "
                "INCONNU : l'étendue des données exfiltrées (le mémo le dit) et comment des données de serveurs de fichiers seraient arrivées sur dc-01 (HYP-007). "
                "T1041 (exfiltration sur le canal C2) n'est pas écarté formellement, mais 203.0.113.28 diffère des IP de commande connues, ce qui soutient un canal distinct."),
    techniques=[("T1048.003", "probable", "sortie en clair (« cleartext ») sur 8080 vers une IP distincte des IP C2")],
    preuves=[(F_LOG, 10, "203.0.113.28:8080 bytes=2469135790 cleartext"), (F_AL, 11, "2,3 Go sortants vers 203.0.113.28 en clair, port 8080")],
    qualif="OBSERVE (volume) ; exfiltration de données : HYPOTHESE FORTE", confiance="moyenne",
    contradictions="I-10 (unités) ; fiche BIN-03 situe l'archive sur le DC alors que le mémo parle de serveurs de fichiers",
    liens="ALERT-009 (+3 h 19), ALERT-005 (+1 h 24) ; IOC-024 relie à BIN-003 par déclaration",
    verifs="Zeek conn.log (orig_bytes vs resp_bytes, durée, history) ; http.log ou PCAP ; taille de l'archive staging ; service sur 8080 ; journal de pare-feu.",
)
A[11] = dict(
    log=11, compte="INCONNU",
    iocs="IOC-016 (static-assets-cache.test), IOC-022 (203.0.113.15, repli), IOC-027, IOC-033/034/035 (certificats, lien déclaré)",
    suspect="Requête d'un serveur interne vers un domaine présenté comme canal de repli, plusieurs jours après la balise principale.",
    conclusion=("OBSERVE : un GET vers https://static-assets-cache.test/ depuis srv-fichiers-02, réponse 200 (taille absente). Le caractère « repli C2 » est une annotation de la source (« (failover C2) ») : "
                "aucune ligne ne montre la perte du C2 principal ni un schéma de balise vers ce domaine. NON DEMONTRE : que ce soit du C2, que le client soit BIN-002 (HYP-005), le processus client. "
                "L'infrastructure de repli (IOC-016, IOC-022) est « vue » dès le 3 mars, trois jours AVANT cet événement (I-11) : cela peut être légitime (infrastructure connue à l'avance) ou signaler un problème de datation."),
    techniques=[("T1008", "probable", "annotation « failover C2 » seule ; sans perte démontrée du canal primaire, la technique reste faiblement étayée"), ("T1071.001", "probable", "requête web 200")],
    preuves=[(F_LOG, 11, "GET https://static-assets-cache.test/ 200 (failover C2)"), (F_AL, 12, "après perte du C2 principal")],
    qualif="OBSERVE (requête) ; repli C2 : HYPOTHESE", confiance="faible à moyenne",
    contradictions="I-11 (infrastructure de repli vue le 3 mars) ; I-07 (hôte srv-fichiers-02 vs BIN-002 sur comptabilite-07)",
    liens="ALERT-004 (canal principal), ALERT-008 (même hôte), IOC-016 « même certificat » (relation certificat déclarée, non étayée par un artefact)",
    verifs="Journaux proxy du C2 principal entre le 5 et le 6 mars (échecs) ; DNS ; certificat TLS du repli (comparaison avec CN=update-service) ; user-agent ; processus client.",
)
A[12] = dict(
    log=12, compte="INCONNU (exécutant de wevtutil non indiqué)",
    iocs="IOC-040 (comptabilite-07) ; aucun IoC dédié",
    suspect="Effacement du journal Security sur le poste d'entrée, deux jours après l'exfiltration.",
    conclusion=("OBSERVE : événement 1102 (journal d'audit effacé) et la commande wevtutil cl Security sur comptabilite-07. L'intitulé de l'alerte parle de « tentative » mais 1102 est produit après un effacement : "
                "l'effacement semble avoir ABOUTI (I-19). CONSEQUENCE : les événements Security antérieurs de ce poste peuvent être perdus : l'absence d'événements Security sur comptabilite-07 n'est pas une preuve d'absence. "
                "NON DEMONTRE : l'auteur, le processus, la présence continue de l'attaquant (HYP-008)."),
    techniques=[("T1685.005", "observée", "1102 + wevtutil cl Security ; la page officielle cite wevtutil cl security ; ancien ID T1070.001 (<= v18) devenu T1685.005 en v19")],
    preuves=[(F_LOG, 12, "1102 audit log cleared / wevtutil cl Security"), (F_AL, 13, "Tentative d'effacement des journaux")],
    qualif="OBSERVE", confiance="élevée pour l'action et pour l'ID courant (T1685.005, vérifié ; le validateur pySigma signale T1070.001 comme invalide)",
    contradictions="I-19 (« tentative » vs 1102) ; identifiant ATT&CK renuméroté (T1070.001 -> T1685.005) ; le mémo daté du 2 mars ne peut pas connaître cet événement (I-02)",
    liens="ALERT-001..004 (même hôte, poste d'entrée) ; ALERT-010 (+1 j 17 h 31)",
    verifs="Compte et processus (Sysmon EID 1, 4688) ; copie des journaux dans le SIEM avant effacement ; état des autres journaux ; contrôle d'autres effacements (104 pour System).",
)

# --------------------------------------------------------------------------- contrôle des preuves + matrice
rows = []
al = list(csv.DictReader(open(os.path.join(SRC, F_AL), encoding="utf-8")))
for r in al:
    n = int(r["alerte"])
    a = A[n]
    # cohérence interne : la ligne de journal citée doit porter le même horodatage et le même hôte
    lg = line(F_LOG, a["log"])
    if not (lg.startswith(r["horodatage"]) and r["hote"] in lg):
        errors.append(f"ALERT-{n:03d}: ligne de journal {a['log']} non concordante avec l'alerte")
    for f, ln, sub in a["preuves"]:
        check(f, ln, sub)
    for tid, _, _ in a["techniques"]:
        pass
    tech_txt = " | ".join(f"{t} [{s}] : {p}" for t, s, p in a["techniques"])
    prop = " ; ".join(t for t, s, p in a["techniques"] if s.startswith(("observée", "probable")))
    prev_t = r["technique_attck"]
    ver = " ; ".join(f"{t.split()[0]} : {ATT[t.split()[0]][0]} (page v{ATT[t.split()[0]][1]}, {ATT[t.split()[0]][3].split(' (')[0]})"
                     for t, s, p in a["techniques"] if t.split()[0] in ATT)
    preuve_txt = " || ".join(f"{f}:{ln} : « {sub} »" for f, ln, sub in a["preuves"])
    rows.append([
        f"ALERT-{n:03d}", f"{F_AL}:{n+1}", f"{F_LOG}:{a['log']}",
        r["horodatage"], "UTC (suffixe Z, connu pour le format) ; fuseau local du site INCONNU ; journal brut : heure ISO identique",
        f"LOG : {line(F_LOG, a['log'])} || ALERTE (détail) : {r['detail']}",
        r["hote"], a["compte"], a["iocs"], a["suspect"],
        f"« {r['intitule']} » ; technique SIEM {prev_t} ; sévérité {r['severite']} ; source {r['source']}",
        a["conclusion"], prop, tech_txt, preuve_txt, ver,
        a["qualif"], a["confiance"], a["contradictions"], a["liens"], a["verifs"],
        "Technique SIEM " + prev_t + " : " + ("RETENUE après examen de la preuve" if prev_t in prop else "NON RETENUE ou rétrogradée"),
    ])

header = ["id", "fichier_source_alerte:ligne", "journal_brut:ligne", "horodatage_original", "fuseau", "observation_brute", "hote", "compte",
          "iocs_concernes", "caractere_suspect", "interpretation_SIEM", "conclusion_independante_analyste", "technique_ATTACK_proposee",
          "detail_techniques_et_statut", "preuve_exacte", "verification_ATTACK_officielle", "qualification", "niveau_de_confiance",
          "contradictions", "liens_autres_alertes", "verifications_complementaires", "comparaison_SIEM"]
with open(os.path.join(OUT, "Matrice-analyse-alertes.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(header)
    w.writerows(rows)

# --------------------------------------------------------------------------- matrice ATT&CK (périmètre alertes)
tech_alerts = {}
for n, a in A.items():
    for t, s, p in a["techniques"]:
        for tid in [x.strip() for x in t.replace("(T1078.002 si compte de domaine)", "").split("/")]:
            tid = tid.split()[0]
            if tid in ATT:
                tech_alerts.setdefault(tid, []).append((n, s, p))
with open(os.path.join(OUT, "Matrice-ATTACK.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["technique_id", "nom_officiel", "url_officielle", "version_page_lue", "derniere_modif_affichee", "date_consultation",
                "statut_verification_officielle", "alertes_et_statut", "perimetre", "limites"])
    for tid in sorted(tech_alerts):
        n_, v_, d_, st_ = ATT[tid]
        url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
        w.writerow([tid, n_, url, v_, d_, "2026-10-06", st_,
                    " ; ".join(f"ALERT-{n:03d} {s} ({p})" for n, s, p in tech_alerts[tid]),
                    "alertes uniquement (fiches binaires non traitées à ce stade)",
                    "Valeurs relevées via l'outil WebFetch (résumé par modèle) : version et date à reconfirmer visuellement avant remise"])
    # techniques des fiches non encore traitées : non incluses volontairement

# --------------------------------------------------------------------------- chronologie provisoire
IOC_CSV = lambda n: f"{F_IOC}:{n+1}"
C = [  # (UTC, heure_originale, artefact, observation, interprétation, confiance, limites, statut)
 ("2026-03-02T06:40:00Z", "2026-03-02T06:40:00Z", IOC_CSV(17), "Domaine helios-energy-portal.test, première vue (IOC-017)", "Infrastructure d'usurpation de la victime préexistante à l'incident : HYPOTHESE", "faible", "« première vue » est la date de découverte par le SOC, pas de création du domaine", "DECLARE (IoC)"),
 ("2026-03-02T07:58:00Z", "2026-03-02T07:58:00Z", IOC_CSV(15) + " ; " + IOC_CSV(23), "Page d'hameçonnage mail-secure-login.test et son IP, première vue (IOC-015, IOC-023)", "Collecte d'identifiants liée au courriel initial : déclaré, non observé", "faible", "Aucun journal ni courriel fourni", "DECLARE (IoC)"),
 ("2026-03-02T08:30:00Z", "2026-03-02T08:30:00Z", F_FICHE + " ; " + IOC_CSV(1), "Première apparition de BIN-001 (facture_mars_2026.xlsm), poste comptabilite-07 (IOC-040)", "Arrivée du classeur : DECLARE", "moyenne", "Échantillon non fourni", "DECLARE"),
 ("2026-03-02T08:31:00Z", "2026-03-02T08:31:00Z", f"{F_LOG}:1 ; {F_AL}:2", "winword.exe lance powershell.exe -enc (IEX) -w hidden", "Exécution PowerShell masquée : observée", "élevée", "Parent winword vs .xlsm (I-18) ; commande tronquée", "OBSERVE (ALERT-001)"),
 ("2026-03-02T08:32:00Z", "2026-03-02T08:32:00Z", IOC_CSV(10), "Charge PowerShell déchiffrée, sha256 (IOC-010)", "Existence d'une charge en mémoire : déclarée", "faible", "Aucune capture fournie", "DECLARE (IoC)"),
 ("2026-03-02T08:41:00Z", "2026-03-02T08:41:00Z", IOC_CSV(4) + " ; " + IOC_CSV(13), "Première vue de BIN-002 et du domaine de téléchargement (IOC-004, IOC-013)", "Concorde avec ALERT-002 (1 min)", "moyenne", "Date de première vue", "DECLARE (IoC)"),
 ("2026-03-02T08:42:00Z", "2026-03-02T08:42:00Z", f"{F_LOG}:2 ; {F_AL}:3", "GET de svchost_update.exe, 200, 421376 octets", "Téléchargement de BIN-002 : transfert observé, exécution non démontrée", "élevée", "Contenu non vu", "OBSERVE (ALERT-002) / CORROBORE (taille)"),
 ("2026-03-02T08:44:00Z", "2026-03-02T08:44:00Z", IOC_CSV(38), "Clé de registre Run\\WinTelemetry, première vue (IOC-038)", "Persistance par clé Run : déclarée (fiche BIN-01), sans alerte", "faible", "Valeur tronquée dans la source", "DECLARE (IoC)"),
 ("2026-03-02T08:46:00Z", "2026-03-02T08:46:00Z", f"{F_LOG}:3 ; {F_AL}:4", "Création de la tâche MicrosoftEdgeUpdateTaskMachine", "Persistance probable : action de la tâche inconnue", "moyenne", "I-20 (format Sysmon)", "OBSERVE (ALERT-003)"),
 ("2026-03-02T09:16:00Z", "2026-03-02T09:16:00Z", f"{F_LOG}:4 ; {F_AL}:5", "Connexion vers 198.51.100.24:443, 0,4 s, 812 octets, étiquetée beacon", "Balise : HYPOTHESE forte ; périodicité non démontrée", "moyenne", "Une seule ligne ; IOC-014 vu à 09:15", "OBSERVE (ALERT-004)"),
 ("2026-03-02T09:20:00Z", "2026-03-02T09:20:00Z", IOC_CSV(21) + " ; " + IOC_CSV(33), "Serveur de commande principal 203.0.113.14 et certificat CN=update-service, première vue", "Infrastructure C2 : déclarée ; relation à 198.51.100.24 non établie (I-12)", "faible", "Aucun artefact certificat", "DECLARE (IoC)"),
 ("2026-03-02T10:30:00Z", "2026-03-02T10:30:00Z", F_MEMO + ":3", "Date d'en-tête du mémo « initial »", "Date NON FIABLE : le mémo décrit des faits du 5 mars (I-02)", "faible", "Version finale ou date d'ouverture ?", "ANOMALIE"),
 ("2026-03-03T02:00:00Z", "2026-03-03T02:00:00Z", IOC_CSV(22), "IP de commande de repli 203.0.113.15, première vue", "Repli connu 3 jours avant ALERT-011 (I-11)", "faible", "Date de première vue", "DECLARE (IoC)"),
 ("2026-03-03T03:22:00Z", "2026-03-03T03:22:00Z", IOC_CSV(16) + " ; " + IOC_CSV(27), "static-assets-cache.test (même certificat) et 198.51.100.61 (passive DNS partagé avec D-04), première vue", "Relations réseau et certificat : déclarées, non étayées", "faible", "Passive DNS non fourni ; référence D-04 non résolue (I-13)", "DECLARE (IoC)"),
 ("2026-03-03T10:12:00Z", "2026-03-03T10:12:00Z", IOC_CSV(25), "198.51.100.55, première vue", "Voir ALERT-006", "faible", "Nature de l'IP INCONNUE (I-05)", "DECLARE (IoC)"),
 ("2026-03-03T10:13:00Z", "2026-03-03T10:13:00Z", f"{F_LOG}:5 ; {F_AL}:7", "Balayage 198.51.100.55 vers 10.20.0.0/16 sur 445 et 3389", "Reconnaissance interne : observée ; origine inconnue (HYP-003/004)", "élevée (balayage) / faible (origine)", "I-05 ; alerte placée après l'alerte 5 dans le fichier (I-01)", "OBSERVE (ALERT-006)"),
 ("2026-03-04T01:47:00Z", "2026-03-04T01:47:00Z", IOC_CSV(26), "203.0.113.44, RDP entrant, première vue (IOC-026)", "Source RDP : externe selon l'IoC, interne selon l'alerte (I-04)", "faible", "Contradiction non résolue", "DECLARE (IoC)"),
 ("2026-03-04T01:48:00Z", "2026-03-04T01:48:00Z (événement : time=01:47, fuseau non précisé)", f"{F_LOG}:6 ; {F_AL}:8", "4624 type 10 pour svc-backup-temp sur srv-fichiers-02", "RDP par un compte créé 36 h plus tard (I-03) : fiabilité CONTESTEE", "moyenne (événement) / faible (conclusion)", "HYP-001/002/012", "OBSERVE (ALERT-007) + ANOMALIE"),
 ("2026-03-04T11:04:00Z", "2026-03-04T11:04:00Z", IOC_CSV(18), "update-win-msft.test, première vue (IOC-018)", "Sens du contexte « nom de tâche planifiée » flou (I-14)", "faible", "-", "DECLARE (IoC)"),
 ("2026-03-04T11:05:00Z", "2026-03-04T11:05:00Z", f"{F_LOG}:7 ; {F_AL}:9", "CreateRemoteThread dans explorer.exe, région RWX, sur srv-fichiers-02", "Injection par thread distant : observée ; sous-technique non démontrée ; initiateur inconnu", "élevée (injection) / faible (reste)", "I-06, I-07", "OBSERVE (ALERT-008)"),
 ("2026-03-04T11:06:00Z", "2026-03-04T11:06:00Z", IOC_CSV(11), "Module injecté (sha256 8772b487...), première vue (IOC-011)", "Module attribué à BIN-002 par le SOC : DECLARE, non corroboré", "faible", "Pas d'échantillon", "DECLARE (IoC)"),
 ("2026-03-05T14:05:00Z", "2026-03-05T14:05:00Z", F_FICHE + " ; " + IOC_CSV(7), "Première apparition de BIN-003 sur dc-01", "Arrivée de l'outil sur le DC : déclarée ; mécanisme d'accès au DC inconnu", "moyenne", "Échantillon non fourni", "DECLARE"),
 ("2026-03-05T14:07:00Z", "2026-03-05T14:07:00Z", f"{F_LOG}:8 ; {F_AL}:6", "Accès à lsass.exe, masque 0x1010", "Lecture mémoire LSASS : observée ; extraction non démontrée", "élevée (accès) / moyenne (extraction)", "I-08 ; alerte hors séquence (I-01)", "OBSERVE (ALERT-005)"),
 ("2026-03-05T14:10:00Z", "2026-03-05T14:10:00Z", IOC_CSV(37) + " ; " + F_AL + ":10", "Création de svc-backup-temp selon le détail de l'alerte et IOC-037", "Date de création : 14:10 (détail) vs 14:12 (journal) (I-09)", "moyenne", "2 min d'écart", "DECLARE"),
 ("2026-03-05T14:12:00Z", "2026-03-05T14:12:00Z", f"{F_LOG}:9 ; {F_AL}:10", "4720 création de svc-backup-temp (4726 « 45m later »)", "Création de compte : observée ; T1543.003 contesté", "moyenne", "I-03, I-09", "OBSERVE (ALERT-009)"),
 ("2026-03-05T14:40:00Z", "2026-03-05T14:40:00Z", IOC_CSV(39), "Fichier C:\\Windows\\Temp\\~df3a9.tmp, première vue", "Préparation avant exfiltration : déclarée", "faible", "Taille et contenu inconnus", "DECLARE (IoC)"),
 ("2026-03-05T14:45:00Z", "2026-03-05T14:45:00Z", IOC_CSV(12), "Archive chiffrée (sha256 a0e1f129...), première vue", "Archive d'exfiltration : déclarée", "faible", "Pas d'échantillon", "DECLARE (IoC)"),
 ("2026-03-05T14:55:00Z", "2026-03-05T14:55:00Z (détail d'alerte)", F_AL + ":10", "Suppression de svc-backup-temp selon le détail ; 14:57 selon le calcul « 45m later » depuis 14:12", "Compte éphémère : durée ~45 min", "moyenne", "Heure du 4726 absente du journal", "DECLARE (alerte)"),
 ("2026-03-05T15:30:00Z", "2026-03-05T15:30:00Z", IOC_CSV(24), "203.0.113.28, première vue (IOC-024)", "Concorde avec ALERT-010 (1 min)", "moyenne", "-", "DECLARE (IoC)"),
 ("2026-03-05T15:31:00Z", "2026-03-05T15:31:00Z", f"{F_LOG}:10 ; {F_AL}:11", "Sortie de 2 469 135 790 octets vers 203.0.113.28:8080, cleartext", "Exfiltration probable ; contenu et étendue inconnus", "moyenne", "I-10", "OBSERVE (ALERT-010)"),
 ("2026-03-06T03:10:00Z", "2026-03-06T03:10:00Z", f"{F_LOG}:11 ; {F_AL}:12", "GET vers static-assets-cache.test, 200, annotation failover C2", "Repli C2 : HYPOTHESE", "faible à moyenne", "I-11", "OBSERVE (ALERT-011)"),
 ("2026-03-06T09:00:00Z", "2026-03-06T09:00:00Z", IOC_CSV(28), "203.0.113.60 rapprochée d'un rapport public (D4)", "Non vérifiable : HYPOTHESE", "très faible", "Source externe non fournie", "DECLARE (IoC)"),
 ("2026-03-06T10:00:00Z", "2026-03-06T10:00:00Z", IOC_CSV(35), "Certificat pivot vers une campagne de janvier 2026 (C4)", "Non vérifiable : HYPOTHESE", "très faible", "Campagne non fournie", "DECLARE (IoC)"),
 ("2026-03-07T09:02:00Z", "2026-03-07T09:02:00Z", f"{F_LOG}:12 ; {F_AL}:13", "1102 journal Security effacé, wevtutil cl Security, sur comptabilite-07", "Effacement abouti probable ; présence continue de l'attaquant : HYPOTHESE", "élevée (action)", "I-19", "OBSERVE (ALERT-012)"),
]
prev = ""
for c in C:
    if c[0] < prev:
        errors.append(f"CHRONOLOGIE non triée à {c[0]}")
    prev = c[0]
with open(os.path.join(OUT, "Chronologie.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["id", "heure_normalisee_UTC", "heure_originale", "artefact_et_ligne", "observation", "interpretation", "niveau_de_confiance", "limites", "statut"])
    for i, c in enumerate(C, 1):
        w.writerow([f"CHR-{i:03d}", c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]])

if errors:
    print("ECHEC DU CONTROLE DES PREUVES :")
    for e in errors:
        print(" -", e)
    sys.exit(1)
n_preuves = sum(len(a["preuves"]) for a in A.values())
print(f"OK : 12 alertes analysees, {n_preuves} preuves relues dans les sources (0 introuvable), {len(C)} evenements de chronologie (tries), {len(tech_alerts)} techniques ATT&CK.")
