#!/usr/bin/env python3
"""Génère Manifeste-OpenCTI.json (PROPOSITION, rien n'est écrit dans OpenCTI) et ses comptages.

Source : 02-Artefacts/Inventaire-IoC.csv et 04-Analyse/Matrice-analyse-alertes.csv. Aucune connexion réseau.
Le script échoue si les comptages ne se recoupent pas (40 entrées IoC toutes affectées, aucune oubliée ni doublée).
Relancer : python3 05-Plateformes/generer-manifeste-opencti.py
"""
import csv, json, os, sys, collections

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ioc = {r["id"]: r for r in csv.DictReader(open(os.path.join(BASE, "02-Artefacts", "Inventaire-IoC.csv"), encoding="utf-8"))}
N = lambda i: ioc[f"IOC-{i:03d}"]["valeur_normalisee"]

# ------------------------------------------------------------------ OBSERVABLES (rubrique Observations)
obs = []   # (id_local, type OpenCTI/STIX, valeur, entrées IoC sources, remarque)
def add(idl, typ, val, srcs, rem=""):
    obs.append(dict(id_local=idl, type=typ, valeur=val, iocs_sources=[f"IOC-{s:03d}" for s in srcs], remarque=rem))

add("OBS-F-BIN001", "StixFile", {"name": "facture_mars_2026.xlsm", "size": 68242, "hashes": {"MD5": N(3), "SHA-1": N(2), "SHA-256": N(1)}}, [1, 2, 3], "empreintes DECLAREES par la fiche ; AUCUN contenu binaire, AUCUN Artifact")
add("OBS-F-BIN002", "StixFile", {"name": "svchost_update.exe", "size": 421376, "hashes": {"MD5": N(6), "SHA-1": N(5), "SHA-256": N(4)}}, [4, 5, 6], "taille corroborée par la ligne Squid ; échantillon non fourni")
add("OBS-F-BIN003", "StixFile", {"name": "rundll32_helper.dll", "size": 210944, "hashes": {"MD5": N(9), "SHA-1": N(8), "SHA-256": N(7)}}, [7, 8, 9], "échantillon non fourni")
add("OBS-F-PS", "StixFile", {"hashes": {"SHA-256": N(10)}}, [10], "charge PowerShell déchiffrée en mémoire, DECLAREE (aucune capture)")
add("OBS-F-MOD", "StixFile", {"hashes": {"SHA-256": N(11)}}, [11], "module injecté, DECLARE rattaché à BIN-002 par le SOC, non corroboré")
add("OBS-F-ARC", "StixFile", {"hashes": {"SHA-256": N(12)}}, [12], "archive chiffrée avant exfiltration, DECLAREE")
# Domain-Name : NON CREES comme observables (connecteur Google DNS en mode automatique, sans garde TLP : la valeur serait transmise à Google).
# Les domaines IoC 13 à 18 restent représentés par MISP (attributs) et, pour 13 et 16, par un indicateur sans observable.
for i in range(19, 29):
    add(f"OBS-IP-{i}", "IPv4-Addr", N(i), [i], "plage de documentation RFC 5737" + (" ; NATURE INCONNUE (I-05)" if i == 25 else " ; source RDP INCONNUE (I-04)" if i == 26 else " ; non vérifiable (D4)" if i == 28 else ""))
for i in range(29, 33):
    add(f"OBS-U-{i}", "Url", N(i), [i], "URL en .test")
add("OBS-U-X1", "Url", "https://static-assets-cache.test/", [], "EXTRAIT de la ligne de journal 11 (alerte 11), absent des 40 IoC ; indicateur extrait pendant l'analyse")
for i in range(33, 36):
    add(f"OBS-X-{i}", "X509-Certificate", {"hashes": {"SHA-1": N(i)}}, [i], "empreinte seule, aucun certificat fourni" + (" ; pivot non vérifiable (C4)" if i == 35 else ""))
add("OBS-ACC", "User-Account", {"account_login": N(37)}, [37], "compte du SI victime, chronologie contradictoire (I-03)")
add("OBS-F-TMP", "StixFile", {"name": "~df3a9.tmp", "parent_directory": "C:\\Windows\\Temp"}, [39], "nom seul, aucun hash ; lié au répertoire OBS-DIR")
add("OBS-DIR", "Directory", {"path": "C:\\Windows\\Temp"}, [39], "répertoire de l'IoC 39")

exclus = [
    dict(ioc="IOC-013..018", raison="6 noms de domaine : pas d'observable Domain-Name (Google DNS en mode automatique sans garde TLP transmettrait la valeur à un tiers) ; présents dans MISP, et indicateurs IND-04 et IND-08 sans observable"),
    dict(ioc="IOC-036", raison="nom de tâche planifiée : aucun type d'observable adapté dans la liste réelle (le type « Texte » dénaturerait la donnée) ; décrit dans le rapport et la Note"),
    dict(ioc="IOC-038", raison="clé de registre dont la valeur source est tronquée (« HKCU\\...\\Run\\WinTelemetry ») : un observable Windows-Registry-Key invalide serait une donnée inventée"),
    dict(ioc="IOC-040", raison="actif victime (comptabilite-07), pas un observable offensif : représenté comme entité System"),
]
covered = collections.Counter(s for o in obs for s in o["iocs_sources"])
for e in exclus:
    if e["ioc"] == "IOC-013..018":
        for i in range(13, 19): covered[f"IOC-{i:03d}"] += 1
    else:
        covered[e["ioc"]] += 1
for i in range(1, 41):
    if covered[f"IOC-{i:03d}"] < 1:
        sys.exit(f"IOC-{i:03d} non affecté")
# IOC-039 est volontairement dans deux objets (fichier + répertoire)
multi = {k: v for k, v in covered.items() if v > 1}
if set(multi) != {"IOC-039"}:
    sys.exit(f"affectations multiples inattendues : {multi}")

# ------------------------------------------------------------------ INDICATORS
IND = [
    ("IND-01", "[file:hashes.'SHA-256' = '%s']" % N(1), "BIN-001 dropper (fiche)", ["ART-002", "IOC-001"], "faible (15)", "échantillon non fourni ; hash non recalculable ; verdict = déclaration de la fiche", ["OBS-F-BIN001"]),
    ("IND-02", "[file:hashes.'SHA-256' = '%s']" % N(4), "BIN-002 balise (fiche)", ["ART-002", "IOC-004", "journal:2"], "faible (15)", "taille corroborée par Squid mais pas le hash ; échantillon non fourni", ["OBS-F-BIN002"]),
    ("IND-03", "[file:hashes.'SHA-256' = '%s']" % N(7), "BIN-003 outil d'identifiants (fiche)", ["ART-002", "IOC-007"], "faible (15)", "outil générique « très largement partagé » selon la fiche ; échantillon non fourni", ["OBS-F-BIN003"]),
    ("IND-04", "[domain-name:value = '%s']" % N(13), "domaine de téléchargement de BIN-002", ["IOC-013", "ALERT-002", "journal:2"], "moyenne (50)", "« jamais vu » non vérifiable ; résolution vers 198.51.100.23 déclarée ; SANS observable (Google DNS)", []),
    ("IND-05", "[url:value = '%s']" % N(29), "URL de la seconde charge", ["IOC-029", "ALERT-002", "journal:2"], "moyenne (50)", "contenu de la réponse non vu ; exécution non démontrée", ["OBS-U-29"]),
    ("IND-06", "[ipv4-addr:value = '%s']" % N(20), "destination de la connexion de balise (ALERT-004)", ["IOC-020", "ALERT-004", "journal:4"], "faible (15)", "une seule connexion ; « beacon » = annotation de la source ; rôle de C2 non démontré (I-12)", ["OBS-IP-20"]),
    ("IND-07", "[ipv4-addr:value = '%s']" % N(24), "destination de la sortie de 2 469 135 790 octets (ALERT-010)", ["IOC-024", "ALERT-010", "journal:10"], "moyenne (50)", "contenu et nature de l'exfiltration inconnus ; direction du champ bytes non précisée", ["OBS-IP-24"]),
    ("IND-08", "[domain-name:value = '%s']" % N(16), "domaine du « repli C2 » (ALERT-011)", ["IOC-016", "ALERT-011", "journal:11"], "faible (15)", "« failover C2 » = annotation ; perte du C2 principal non montrée (I-11) ; SANS observable (Google DNS)", []),
]
ind_excluded = "Les 32 autres observables (dont tous les IPv4 hors 198.51.100.24 et 203.0.113.28, les domaines d'hameçonnage et d'usurpation, les certificats, le compte, les fichiers dérivés) restent des OBSERVABLES : aucun indicateur n'est justifié par un artefact d'observation ou une vérification."

# ------------------------------------------------------------------ OBJETS PAR RUBRIQUE
rubriques = {
    "Analyses": {"Report": 1, "Note": 3,  # N-ALERTES (registre des 12 alertes), N-LIMITES (limites et incohérences), N-ATTRIB (attribution hypothétique)
      "Grouping": 0},
    "Evenements": {"Incident": 1, "Observed-Data": 4, "Sighting": 4},
    "Observations": {"Observables (hors Artifact)": len(obs), "Indicator": len(IND), "Artifact": 0},
    "Support (hors des trois rubriques, non comptés comme objets analytiques)": {"Identity-Organization": 3, "Identity-System": 3, "Label": 6, "External-Reference": 11},
}
relations = {
    "based-on (Indicator vers Observable)": sum(1 for i in IND if i[6]),
    "related-to (Indicator vers Incident)": len(IND),
    "targets (Incident vers Organization victime)": 1,
    "targets (Incident vers System)": 3,
    "uses (Incident vers Attack-Pattern existant, techniques OBSERVEES)": 8,
}
sightings = [
    dict(id_local="SIG-01", indicateur="IND-04", ou="System comptabilite-07", first_last="2026-03-02T08:42:00Z", count=1, preuves=["ALERT-002", "journal:2"]),
    dict(id_local="SIG-02", indicateur="IND-06", ou="System comptabilite-07", first_last="2026-03-02T09:16:00Z", count=1, preuves=["ALERT-004", "journal:4"]),
    dict(id_local="SIG-03", indicateur="IND-07", ou="System dc-01", first_last="2026-03-05T15:31:00Z", count=1, preuves=["ALERT-010", "journal:10"]),
    dict(id_local="SIG-04", indicateur="IND-08", ou="System srv-fichiers-02", first_last="2026-03-06T03:10:00Z", count=1, preuves=["ALERT-011", "journal:11"]),
]
observed = [
    dict(id_local="OD-02", alerte="ALERT-002", first_last="2026-03-02T08:42:00Z", number_observed=1, objets=["OBS-U-29"], brut="Squid: GET https://cdn-svc-update.test/win/svchost_update.exe 200 421376"),
    dict(id_local="OD-04", alerte="ALERT-004", first_last="2026-03-02T09:16:00Z", number_observed=1, objets=["OBS-IP-20"], brut="Zeek: conn 198.51.100.24:443 duration=0.4 orig_bytes=812 (beacon)"),
    dict(id_local="OD-10", alerte="ALERT-010", first_last="2026-03-05T15:31:00Z", number_observed=1, objets=["OBS-IP-24"], brut="Zeek: large outbound 203.0.113.28:8080 bytes=2469135790 cleartext"),
    dict(id_local="OD-11", alerte="ALERT-011", first_last="2026-03-06T03:10:00Z", number_observed=1, objets=["OBS-U-X1"], brut="Squid: GET https://static-assets-cache.test/ 200 (failover C2)"),
]
alertes_traitement = {
    "ALERT-001": "ligne du registre N-ALERTES (commande tronquée : pas d'Observed Data) ; T1059.001 et T1564.003 via Incident uses",
    "ALERT-002": "Observed Data OD-02 + Sighting SIG-01 (si IND-04 approuvé) ; T1105 via Incident uses",
    "ALERT-003": "registre N-ALERTES seulement (aucun observable adapté) ; T1053.005 via Incident uses",
    "ALERT-004": "Observed Data OD-04 + Sighting SIG-02",
    "ALERT-005": "registre N-ALERTES seulement (accès mémoire : aucun observable) ; T1003.001 NON liée (probable, extraction non démontrée)",
    "ALERT-006": "registre N-ALERTES seulement (nature de 198.51.100.55 inconnue : pas d'Observed Data) ; T1046 via Incident uses",
    "ALERT-007": "registre N-ALERTES seulement (chronologie contradictoire I-03) ; T1021.001 via Incident uses",
    "ALERT-008": "registre N-ALERTES seulement ; T1055 (parent) via Incident uses ; T1055.012 NON utilisée",
    "ALERT-009": "registre N-ALERTES seulement (I-03) ; aucune technique liée (T1136.002 probable, T1543.003 écartée)",
    "ALERT-010": "Observed Data OD-10 + Sighting SIG-03",
    "ALERT-011": "Observed Data OD-11 + Sighting SIG-04",
    "ALERT-012": "registre N-ALERTES seulement ; T1070.001 liée seulement après vérification officielle du nom et de l'ID",
}
if len(alertes_traitement) != 12:
    sys.exit("12 alertes attendues")

manifest = dict(
    statut="PROPOSITION : NON APPROUVE, NON EXECUTE, AUCUNE ECRITURE DANS OPENCTI",
    cible=dict(plateforme="OpenCTI 6.9.21 (édition Communauté, licence d'essai expirée)", url="http://172.16.0.4:8180",
               instance_ecriture="A DECIDER (option A instance isolée locale recommandée ; option B production avec garde-fous, voir 99-Historique/Plan-modelisation-OpenCTI.md)"),
    noms_exacts=dict(report="[CHALLENGE FICTIF] Helios Energy — Investigation CTI", incident="[CHALLENGE FICTIF] Helios Energy — Intrusion"),
    rapport=dict(type_propose="internal-report", published="2026-10-06 (date de rédaction, PAS une date d'incident)", statut_workflow="NEW",
                 contenu_prevu=["contexte et périmètre", "observations et conclusions documentées", "sources", "limites et incohérences", "attribution hypothétique (identifiée comme telle)", "références aux entités et relations"],
                 pieces_jointes_futures="rapports stratégique et tactique SEULEMENT après production réelle et contrôle (non fournis à ce jour)"),
    incident=dict(first_seen="2026-03-02T08:31:00Z (première observation du dossier : ALERT-001 ; NON début certain de l'intrusion)",
                  last_seen="2026-03-07T09:02:00Z (dernière observation du dossier : ALERT-012 ; NON fin certaine)",
                  severity="non renseignée", incident_type="non renseigné", dates_non_renseignees=["début réel", "fin réelle", "date de détection par le SOC (le mémo est daté du 2 mars mais décrit des faits postérieurs, I-02)"],
                  impacts_soutenus=["exécution d'une commande PowerShell encodée et masquée sur comptabilite-07", "accès mémoire à lsass.exe sur dc-01", "création puis suppression d'un compte sur dc-01", "sortie de 2 469 135 790 octets vers 203.0.113.28:8080 depuis dc-01", "effacement du journal Security de comptabilite-07"],
                  impacts_non_demontres=["contenu et étendue des données exfiltrées", "vol effectif d'identifiants", "présence continue de l'attaquant", "atteinte d'un serveur de fichiers autre que par les événements de srv-fichiers-02"]),
    traitement_des_12_alertes=alertes_traitement,
    observables=obs, exclus_observables=exclus,
    indicateurs=[dict(id_local=a, pattern=b, contexte_menace=c, sources=d, confiance_analyste=e, limites=f, based_on=g) for a, b, c, d, e, f, g in IND],
    indicateurs_non_crees=ind_excluded,
    observed_data=observed, sightings=sightings,
    separation_rejeu_wazuh=dict(auteur_dossier="[CHALLENGE FICTIF] Dossier pédagogique (SOC Helios)", auteur_analyse="[CHALLENGE FICTIF] Équipe CTI",
                                auteur_rejeu_futur="[CHALLENGE FICTIF] Rejeu Wazuh (laboratoire) : créé SEULEMENT lors d'un rejeu approuvé, jamais l'identité de production « Wazuh »",
                                labels=["challenge:helios-fictif", "challenge:source=dossier-pedagogique", "challenge:source=rejeu-wazuh", "analytic:observed", "analytic:hypothesis", "analytic:declared-unverified"],
                                note="labels et auteurs = traçabilité et filtrage, PAS une isolation technique"),
    comptages_par_rubrique=rubriques, relations_envisagees=relations,
    total_objets_dont_rubriques=sum(sum(v.values()) for k, v in rubriques.items()),
    total_relations=sum(relations.values()) + len(sightings),
    exclusions_globales=["aucun Artifact (aucun contenu binaire)", "aucun Intrusion-Set / Threat-Actor / Malware de production lié (attribution = hypothèse, consignée en Note)", "aucune relation vers FIN7 ou Carbanak", "aucun Grouping", "aucun incident par alerte", "aucun sighting par alerte (4 sur 12, justifiés)", "aucun Artifact ni YARA/Sigma importé"],
)
json.dump(manifest, open(os.path.join(BASE, "05-Plateformes", "Manifeste-OpenCTI.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print("observables", len(obs), "| indicateurs", len(IND), "| observed data", len(observed), "| sightings", len(sightings))
print("par rubrique :", {k: sum(v.values()) for k, v in rubriques.items()})
print("relations :", sum(relations.values()), "+", len(sightings), "sightings")
print("40 entrées IoC toutes affectées (IOC-039 compté dans 2 objets, IOC-036/038/040 exclus ou en entité).")
