#!/usr/bin/env python3
"""Compose les textes du rapport et des notes OpenCTI à partir de l'analyse (aucun réseau). Sortie : Textes-OpenCTI.json"""
import csv, json, os
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
al = list(csv.DictReader(open(os.path.join(B, "04-Analyse", "Matrice-analyse-alertes.csv"), encoding="utf-8")))
reg = ["| Alerte | Source (fichier:ligne) | Journal brut | Horodatage (UTC) | Technique SIEM | Technique retenue (équipe) | Qualification |", "|---|---|---|---|---|---|---|"]
for r in al:
    sie = r["interpretation_SIEM"].split("technique SIEM ")[1].split(" ;")[0]
    reg.append(f"| {r['id']} | {r['fichier_source_alerte:ligne']} | {r['journal_brut:ligne']} | {r['horodatage_original']} | {sie} | {r['technique_ATTACK_proposee']} | {r['qualification']} |")
N_AL = ("Registre des 12 alertes du dossier pédagogique. Chaque alerte garde son identifiant et sa preuve ; AUCUNE n'est un incident distinct. "
        "Les techniques du SIEM n'ont pas été reprises telles quelles : T1055.012 (alerte 8) et T1543.003 (alerte 9) sont écartées ; T1070.001 est devenu T1685.005 dans ATT&CK v19. "
        "Ces alertes sont les alertes FOURNIES, à ne pas confondre avec les alertes générées plus tard par le rejeu Wazuh (groupe helios_challenge, règles 130101 à 130115).\n\n" + "\n".join(reg))
N_LIM = ("21 incohérences ou réserves (I-01 à I-21) : alerte 5 hors séquence ; mémo daté du 2 mars décrivant des faits des 5 à 7 mars ; compte svc-backup-temp utilisé le 4 mars à 01:47 et créé le 5 mars à 14:12 (I-03) ; "
         "source RDP interne selon l'alerte, externe selon l'IoC (I-04) ; IP publique source d'un balayage interne (I-05) ; T1055.012 contesté (CreateRemoteThread) ; parent winword.exe pour un classeur .xlsm (I-18) ; "
         "alerte « tentative » pour un effacement effectif (I-19). Blocages : 3 fiches binaires et 0 échantillon ; journal Security de comptabilite-07 effacé le 7 mars ; dates = bornes d'observation, pas début ni fin certains.")
N_ATT = ("ATTRIBUTION HYPOTHÉTIQUE : INCONNUE. Conclusion : cluster non attribué. Aucune observation n'est spécifique à un acteur ; aucune source indépendante n'existe dans le lot. "
         "La piste annoncée par le LISEZ-MOI du dossier pédagogique est une indication, pas une preuve. Hypothèse comparée : cluster cybercriminel à finalité probablement lucrative (confiance faible à moyenne) ; acteur étatique non soutenu. "
         "Aucune relation vers un acteur ou un groupe de production n'a été créée.")
CONTENT = f"""# [CHALLENGE FICTIF] Helios Energy : investigation CTI

**Données fictives.** Victime fictive ; indicateurs en plages de documentation (RFC 5737) et domaines `.test`. Aucun élément n'est un renseignement réel.

## 1. Contexte et périmètre
Incident INC-2026-0302 : intrusion observée du 2 mars 2026 (08:31Z) au 7 mars 2026 (09:02Z). **Ces dates sont des bornes d'observation du dossier**, pas le début ni la fin certains. Périmètre : 40 IoC, 12 alertes SIEM, 3 fiches de binaires (0 échantillon), 1 mémo, 1 journal brut.

## 2. Synthèse
Chaîne observée sur trois hôtes : exécution PowerShell masquée sur comptabilite-07, téléchargement d'un exécutable, tâche planifiée, accès mémoire à LSASS et création d'un compte sur dc-01, sortie de 2 469 135 790 octets vers 203.0.113.28:8080, effacement du journal Security. Contenu exfiltré, vol effectif d'identifiants et présence continue : non démontrés.

## 3. Observations et conclusions documentées
Voir l'incident, les 12 lignes du registre N-ALERTES (note), les observables et indicateurs rattachés. Techniques observées : T1059.001, T1564.003, T1105, T1053.005, T1046, T1021.001, T1055 (sous-technique non démontrée), T1685.005.

## 4. Sources
Dossier d'artefacts (7 fichiers, références ART-001 à ART-007) ; documentation officielle MITRE ATT&CK v19. Cotation Admiralty de l'équipe : sources C (provisoire), informations 3 à 6 ; aucune information ne dépasse 3.

## 5. Limites et incohérences
{N_LIM}

## 6. Attribution hypothétique
{N_ATT}

## 7. Références aux entités
Incident, systèmes comptabilite-07, srv-fichiers-02, dc-01, victime fictive, indicateurs IND-01 à IND-08 (historiques, expirés), observables, données observées, détections (sightings) des alertes 2, 4, 10 et 11 et relations `uses` vers les techniques observées.

## 8. Rapports produits
Les rapports stratégique et tactique ne sont rattachés qu'après production et contrôle des PDF (voir la section Fichiers du rapport).
"""
json.dump({"content": CONTENT, "n_alertes": N_AL, "n_limites": N_LIM, "n_attrib": N_ATT,
           "description": "[CHALLENGE FICTIF] Investigation CTI de l'incident INC-2026-0302 : cluster NON ATTRIBUÉ, dates = bornes d'observation, données fictives. Voir le contenu pour les limites."}, open(os.path.join(B, "05-Plateformes", "Textes-OpenCTI.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("textes écrits :", len(CONTENT), "caractères")
