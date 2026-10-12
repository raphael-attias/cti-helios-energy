#!/usr/bin/env python3
"""Compose Rapport-tactique.md depuis les CSV/JSON de la mission (les tableaux ne sont jamais ressaisis à la main).
Exécuter : python3 08-Rapports/composer-rapport-tactique.py"""
import csv, json, os
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rd = lambda p: list(csv.DictReader(open(os.path.join(B, p), encoding="utf-8")))
al = rd("04-Analyse/Matrice-analyse-alertes.csv"); att = rd("04-Analyse/Matrice-ATTACK.csv"); reg = rd("07-Detection-Tests/Registre-regles.csv"); syn = rd("07-Detection-Tests/resultats/synthese-par-regle.csv")
chr_ = rd("04-Analyse/Chronologie.csv")
ids = {}
def cut(s, n): return s if len(s) <= n else s[:n - 1] + "…"

tl = ["| Heure UTC (03-0x) | Événement | Statut | Confiance |", "|---|---|---|---|"]
for r in chr_:
    tl.append(f"| {r['heure_normalisee_UTC'][5:16].replace('T', ' ')} | {cut(r['observation'], 100)} | {r['statut'].split(' (')[0]} | {r['niveau_de_confiance'].split(' (')[0]} |")
SHORT = {1: "winword.exe lance powershell.exe -enc (préfixe = IEX) -w hidden ; parent incohérent avec un .xlsm", 2: "GET HTTP 200 d'un .exe de 421376 octets (taille = fiche BIN-02) ; exécution non démontrée",
 3: "création de la tâche MicrosoftEdgeUpdateTaskMachine ; action de la tâche inconnue", 4: "UNE connexion 443 de 0,4 s, 812 octets ; périodicité non démontrée",
 5: "accès à lsass.exe, masque 0x1010 (lecture mémoire) ; extraction effective non démontrée", 6: "balayage 445/3389 de 10.20.0.0/16 par 198.51.100.55 ; nature de la source inconnue",
 7: "4624 type 10 pour svc-backup-temp, source réseau absente ; compte créé 36 h plus tard", 8: "CreateRemoteThread dans explorer.exe (RWX) : injection par thread distant ; hollowing non démontré",
 9: "4720 puis 4726 de svc-backup-temp sur dc-01 : création de compte, pas de service", 10: "2 469 135 790 octets vers 203.0.113.28:8080 en clair ; contenu inconnu",
 11: "GET 200 vers static-assets-cache.test annoté « failover C2 » ; perte du C2 principal non montrée", 12: "1102 + wevtutil cl Security : journal effacé (l'alerte dit « tentative »)"}
alt = ["| Alerte | Hôte | Constat indépendant | Technique retenue | Confiance |", "|---|---|---|---|---|"]
for r in al:
    conc = SHORT[int(r['id'][-3:])]
    alt.append(f"| {r['id'][-3:]} | {r['hote']} | {conc} | {cut(r['technique_ATTACK_proposee'].replace(' (T1078.002 si compte de domaine)', ''), 22)} | {cut(r['niveau_de_confiance'].split(' ; ')[0], 40)} |")
fich = []
for r in al:
    fich.append(f"### Alerte {int(r['id'][-3:])} : {r['hote']} ({r['horodatage_original']})\n\n"
                f"- **Observation brute.** `{cut(r['observation_brute'].split(' || ')[0].replace('LOG : ', ''), 170)}`\n"
                f"- **Preuve exacte.** {cut(r['preuve_exacte'].split(' || ')[0], 150)}\n"
                f"- **Interprétation.** {cut(r['conclusion_independante_analyste'], 520)}\n"
                f"- **Technique et statut.** {cut(r['detail_techniques_et_statut'], 330)}\n"
                f"- **Qualification, confiance.** {r['qualification']} ; {r['niveau_de_confiance']}.\n"
                f"- **Contradictions.** {cut(r['contradictions'], 260)}\n"
                f"- **À vérifier.** {cut(r['verifications_complementaires'], 260)}\n")
at = ["| Technique | Nom (ATT&CK v19) | Statut | Alertes |", "|---|---|---|---|"]
for r in att:
    at.append(f"| {r['technique_id']} | {cut(r['nom_officiel'], 52)} | {cut(r['alertes_et_statut'].split(' (')[0], 30)} | {len(r['alertes_et_statut'].split(' ; '))} |")
sig = ["| DET | Règle | Fondement | Tests réels / synthétiques+ / négatifs | Résultat |", "|---|---|---|---|---|"]
res = {s["det"]: s for s in syn}
for r in reg:
    s = res[r["det"]]
    sig.append(f"| {r['det']} | {cut(r['titre'], 56)} | {r['fondement']} | {s['tp']} positifs / {s['tn']} négatifs | 0 écart ({s['evenements_logsource']} événements du logsource) |")
ing = open(os.path.join(B, "05-Plateformes", "Textes-OpenCTI.json"), encoding="utf-8")

md = f"""# Rapport tactique : intrusion INC-2026-0302 (Helios Energy, fictif)

**Destinataires : SOC et CTI. Version finale du 2026-10-07. Données fictives. Classification de travail : TLP:AMBER (voir la note de partage).**
Statuts : OBSERVÉ / CORROBORÉ / HYPOTHÈSE / INCONNU / NON TESTÉ. Chaque conclusion suit le schéma observation, preuve, interprétation, confiance, limite.

## 1. Résumé

Le dossier décrit, du 2 au 7 mars 2026 (**bornes d'observation, pas début ni fin certains**), une chaîne sur trois hôtes : exécution PowerShell masquée sur comptabilite-07, téléchargement d'un exécutable de 421376 octets, tâche planifiée, accès mémoire à LSASS et création d'un compte sur dc-01, sortie de 2 469 135 790 octets vers 203.0.113.28:8080, effacement du journal Security. **Cluster non attribué.** Les trois fiches de binaires ne s'accompagnent d'aucun échantillon. 21 incohérences du dossier sont documentées, dont un compte utilisé 36 h avant sa création.

## 2. Méthodologie et sources

Inventaire par script avec empreintes des 7 fichiers (originaux inchangés) ; analyse indépendante de chaque alerte avec **29 preuves relues automatiquement** dans les originaux ; techniques ATT&CK reconstruites puis vérifiées sur attack.mitre.org (ATT&CK v19, publiée le 28 avril 2026 ; v18.1 en vigueur lors de l'incident) ; cotation Admiralty séparant fiabilité de la source et crédibilité de l'information. Aucune valeur d'IoC n'a été transmise à un service tiers ; aucun binaire n'a été manipulé (il n'y en a pas).

## 3. Inventaire et intégrité

40 IoC (0 doublon, 0 invalide) ; 12 alertes (toutes retrouvées dans le journal brut) ; 3 fiches binaires (9 empreintes retrouvées dans le CSV) ; 1 mémo ; 1 journal brut de 372 lignes (12 utiles, 360 de bruit du 2 mars). Écarts majeurs : alerte 5 hors séquence, mémo daté avant les faits (I-02), compte svc-backup-temp utilisé avant sa création (I-03), source du RDP interne ou externe selon l'artefact (I-04), IP publique source d'un balayage interne (I-05), parent winword.exe pour un `.xlsm` (I-18). **Ces anomalies sont des défauts de données, pas des indices contre l'attaquant** ; les originaux n'ont pas été corrigés. Détail : `02-Artefacts/Integrite-et-provenance.md`.

## 4. Chronologie (extrait des observations)

{chr(10).join(tl)}

Les « premières vues » des IoC sont des dates de découverte, pas des heures d'événement. La chronologie dépend de HYP-001 (compte préexistant) et HYP-002 (horloges désalignées).

## 5. Analyse des 12 alertes

{chr(10).join(alt)}

Les techniques du SIEM ne sont pas reprises : **T1055.012 (alerte 8)** est contestée (la ligne exacte est `CreateRemoteThread into explorer.exe RWX region` ; le Process Hollowing crée un processus suspendu et n'est pas démontré ; on conclut à une injection par thread distant, T1055 au niveau parent) ; **T1543.003 (alerte 9)** est écartée (c'est la création d'un compte, 4720, donc T1136.002 probable) ; **T1070.001 est devenu T1685.005** dans ATT&CK v19. Le détail des 22 colonnes est dans `04-Analyse/Matrice-analyse-alertes.csv` ; fiches ci-dessous (observation, preuve, interprétation, confiance, limite).

{chr(10).join(fich)}

## 6. Analyse des fiches binaires (« analyse des fiches fournies »)

BIN-001 (dropper, 68242 o), BIN-002 (balise, 421376 o, taille corroborée par le journal), BIN-003 (outil LSASS générique selon la fiche). Aucun hash n'est recalculable. Capacités supposées non démontrées : périodicité de 300 s et gigue de 20 % (une seule ligne de balise), hollowing, service Windows, chiffrement du canal.

## 7. Corrélations

| Lien | Nature | Statut |
|---|---|---|
| fiches = CSV (9 empreintes) ; taille 421376 fiche = journal | égalité exacte (même fournisseur) | CORROBORÉ |
| domaine → IP, certificat partagé, passive DNS | relation déclarée | DÉCLARÉ, non exploitable |
| séquences d'horodatages sur un hôte ou entre hôtes | lien temporel | HYPOTHÈSE |
| LSASS, compte, archive, sortie (14:07 à 15:31) | temporel + fiche | HYPOTHÈSE forte |
| MISP, OpenCTI | 0 corrélation externe, 0 entité préexistante | aucun |

## 8. Matrice ATT&CK (alertes uniquement)

{chr(10).join(at)}

*Version ATT&CK : v19 (publiée le 28 avril 2026), lue sur attack.mitre.org le 2026-10-06. Au moment de l'incident (mars 2026), la version en vigueur était la v18.1 : T1685.005 s'appelait alors T1070.001. Détail : `04-Analyse/Version-ATTACK.md`.*

Statuts : « observée » = preuve directe dans un artefact ; « probable » = compatible mais non démontrée (T1003.001, T1071.001, T1008, T1048.003, T1136.002, T1078 : décrites, **non** rattachées dans les graphes).

## 9. Diamond Model

Adversaire INCONNU ; capacités : chaîne PowerShell, implant déclaré, accès LSASS, RDP, effacement de journal ; infrastructure : domaines `.test` et IP RFC 5737 (rôles non démontrés) ; victime : comptabilite-07, srv-fichiers-02, dc-01. Voir `04-Analyse/Diamond-Model.md`.

## 10. Attribution et alternatives

Aucune observation n'est discriminante. Hypothèses comparées : cluster cybercriminel à outillage recoupant une famille connue (affirmation de la fiche, non vérifiable, faible), opérateur opportuniste (compatible), acteur étatique (non soutenu, non exclu). **Conclusion : cluster non attribué.** Confiance élevée dans cette conclusion, faible dans l'hypothèse d'une finalité lucrative (non discriminante : la même chaîne sert l'espionnage). L'indication d'attribution du LISEZ-MOI du dossier pédagogique est consignée à part et n'est pas une preuve. Biais surveillés : confirmation, notoriété, sélection.

## 11. Détection

15 règles Sigma (11 DIRECTES fondées sur un artefact, 3 IOC, 1 CHASSE) : `07-Detection-Tests/sigma/`. Les règles IOC et de chasse **ne prouvent aucune technique observée**.

{chr(10).join(sig)}

**Niveaux de test distincts.** (1) Validation syntaxique : pySigma 1.5.1, 15 règles, 0 alerte de validation après correction de l'identifiant ATT&CK (le validateur a signalé T1070.001 comme invalide, ce qui a révélé la renumérotation). (2) Conversion : backend SQLite, pipeline de renommage de champs (outil de test, pas un déploiement). (3) Test sur événement : base de 410 événements (15 du dossier ou des fiches, 13 positifs synthétiques, 22 négatifs synthétiques, 360 lignes de bruit du dossier) : **0 écart, 0 faux positif sur 410 événements testés** ; les jeux synthétiques sont écrits par l'équipe et ne mesurent aucun taux de production. (4) Wazuh : les décodeurs et règles XML (130101 à 130115) sont des **adaptations manuelles**, pas une conversion. `wazuh-logtest` dans un conteneur de test isolé (sans réseau) : 26 événements conformes sur 45 au premier passage (19 écarts), puis 40 sur 45, puis 45 sur 45 : trois passes de logtest et deux corrections des décodeurs, après deux erreurs de syntaxe signalées par `wazuh-analysisd -t` (champs statiques réservés `url`, `status`, `user` ; limites de la syntaxe OS_Regex ; décodeurs enfants sans prématch ; regex PCRE2) ; rejeu de bout en bout isolé : 27 alertes pour 27 positifs, 0 pour 18 négatifs. En **production** (déploiement ciblé de 2 fichiers, niveaux 4 à 7 pour rester sous le seuil 10 de l'intégration TheHive, redémarrage du manager de 41 s) : `wazuh-logtest` 45 sur 45, rejeu par l'API (3 événements puis 42), **27 alertes** générées, 0 pour les 18 négatifs, **27 documents** retrouvés dans l'indexeur (`wazuh-alerts-4.x-2026.10.06`, groupe `helios_challenge`). Contrôle du dashboard : exécuté le 2026-10-06 en revue de clôture (Discover, `wazuh-alerts-*`, filtre `rule.groups:helios_challenge` : 27 hits). Différences de logique Sigma vers Wazuh : un événement ne produit qu'une alerte (ombrage, 3 cas : W01, W02, W10) ; DET-005 adaptée au nom de tâche ; seuil d'octets approché par 10 chiffres ; pas de normalisation de chemins.

## 12. Plateformes et méthodes d'intégration (état réel)

- **MISP** (production, organisation dédiée CHALLENGE-FICTIF, distribution 0, non publié) : événement 6, 30 attributs + 5 objets (46 attributs), 8 galaxies ATT&CK observées, 0 attribut to_ids, 0 corrélation. **Méthode : API REST** depuis l'hôte MISP avec un utilisateur Publisher dédié ; l'organisation propriétaire a été créée par une **insertion SQL directe, exception documentée et non recommandée**. Écarts : hostname refusé (nom sans point, stocké en texte), taille hors objet, chemin Windows normalisé par MISP, étiquettes personnalisées non créées (droits Publisher).
- **OpenCTI** (production) : 1 rapport (103 objets) + 3 notes (Analyses) ; 1 incident + 4 données observées + 4 détections (Événements) ; 27 observables + 8 indicateurs expirés (Observations) ; 1 enquête (56 entités, 30 relations existantes) et 5 RFI ouvertes sans réponse ; TLP:RED partout, aucun domaine créé comme observable. **Méthode : API GraphQL** (scripts idempotents, jeton d'administration lu dans le conteneur), **ni par le connecteur MISP** (en marche mais sans interrogation de MISP, non repris) **ni par import du bundle**. Contrôle par API et dans l'interface les 2026-10-06 et 2026-10-07 ; réserves : le graphe de connaissance est sur le rapport (pas d'écran graphe pour l'incident), onglet Indicateurs de l'incident vide (relations `related-to`).
- **Wazuh** (production) : 14 décodeurs et 15 règles (130101 à 130115, niveaux 4 à 7) ajoutés comme fichiers nouveaux ; **chemin de test** : logtest en conteneur isolé, logtest en production, rejeu par l'API `POST /events` ; 27 alertes indexées, consultables par `rule.groups: helios_challenge`.
- **STIX** : 152 objets dérivés de l'export MISP réel (`restSearch` STIX 2.1) et d'enrichissements documentés, **non importés** dans une plateforme ; stix2-validator : valide, 0 erreur, 218 avertissements classés (82 identifiants déterministes assumés, 117 propriétés de provenance x_helios_ assumées, 19 bonnes pratiques) ; 548 références résolues. Objets liés : **27 objets de renseignement** (campagne, malwares, outils, infrastructures, techniques, indicateurs) reliés dans une même composante, dont 7 ajoutés le 2026-10-07 sur preuve du journal brut ou des alertes ; 25 si l'on retire les 2 dont la seule base est le texte d'une alerte. Méthode conservatrice de l'équipe, non confirmée par le commanditaire.
- **Non utilisés** : TheHive (aucun objet créé ni importé, vérifié en lecture seule) et Cortex (aucun job pour la mission) ne contribuent à aucun résultat. Détail : `05-Plateformes/Methodes-integration-et-import.md`.

## 13. Confinement et investigations complémentaires

Recommandations conditionnelles (non exécutées, victime fictive) : isoler comptabilite-07 et conserver son image avant remise en état ; rechercher les traces de la tâche `MicrosoftEdgeUpdateTaskMachine` et de la clé Run sur les hôtes du /16 ; revoir les comptes privilégiés si l'extraction LSASS est confirmée ; filtrer le trafic sortant en clair sur 8080 depuis les contrôleurs de domaine ; récupérer les journaux Sysmon, Zeek et proxy complets. À obtenir : échantillons, source du RDP, contenu de la sortie, horloges, date réelle de création de svc-backup-temp, journaux de messagerie.

## 14. Limites

Aucun échantillon ; une seule ligne de balise ; journal Security de comptabilite-07 effacé (absence d'événements ≠ absence d'activité) ; dates = bornes ; cotations sans source indépendante ; tests Sigma et Wazuh sur jeux écrits par l'équipe ; interfaces contrôlées les 2026-10-06 et 2026-10-07 avec réserves (onglet Indicateurs de l'incident vide) ; ATT&CK v19 non encore reflété dans MISP (galaxie T1070.001), Wazuh (T1685.005 inconnue de sa base MITRE, avertissement non bloquant) ni dans certaines entités OpenCTI.

## 15. Références

Règles Sigma complètes : `07-Detection-Tests/sigma/DET-001` à `DET-015`. Registre et résultats : `07-Detection-Tests/Registre-regles.csv`, `Resultats-tests.csv`, `resultats/`. Bundle : `06-STIX-Graphe/Bundle-STIX.json`. Graphe : `06-STIX-Graphe/Graphe-CTI.pdf` (vectoriel) et `Graphe-CTI.png`. Analyse : `04-Analyse/`.

**Annexe : graphe CTI généré depuis le bundle, pivoté de 90° (tourner la page pour le lire).** Version vectorielle lisible : `06-STIX-Graphe/Graphe-CTI.pdf`.

<img src="../06-STIX-Graphe/Graphe-CTI-annexe-portrait.png" style="max-height:238mm; max-width:100%; display:block; margin:auto" alt="Graphe CTI pivoté">
"""
_p = os.path.join(B, "08-Rapports", "Rapport-tactique.md")
if not os.path.exists(_p) or open(_p, encoding="utf-8").read() != md: open(_p, "w", encoding="utf-8").write(md)   # n'écrit que si le contenu change (le PDF n'est alors pas refait)
print("Rapport-tactique.md :", len(md), "caractères")
