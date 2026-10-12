#!/usr/bin/env python3
"""Réécrit 00-Pilotage/Matrice-exigences.csv avec statuts finaux de session et calcule les couvertures SEPAREES (officiel, supplémentaire, optionnel)."""
import csv, os, collections
B = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Vocabulaire final de clôture (2026-10-07) : SATISFAIT ET CONTRÔLÉ, PARTIEL (avec limite), NON SATISFAIT (avec cause), NON APPLICABLE (avec justification)
V, C, E, N, BL, NA = "SATISFAIT ET CONTRÔLÉ", "PARTIEL", "NON SATISFAIT", "NON SATISFAIT", "NON SATISFAIT", "NON APPLICABLE"
AP = "EN ATTENTE D'APPROBATION"
# id, catégorie, exigence, livrable, statut, preuve, contrôle, manque, flags(déclaré, preuve, contrôle) ; valide = oui si statut VALIDÉ
O, S, P = "officielle (lecture du brief ; liste non confirmée)", "demande supplémentaire OpenCTI (non officielle)", "optionnelle"
rows = [
("REQ-01", O, "Inventaire des 40 IoC, comptages séparés", "02-Artefacts/Inventaire-IoC.csv", V, "script + Bilan-comptage.csv", "CSV=JSON 40/40, 0 doublon, sha256 originaux", "aucun enrichissement externe", "oui oui oui"),
("REQ-02", O, "Inventaire des 12 alertes", "02-Artefacts/Inventaire-alertes.csv", V, "script", "12/12 retrouvées dans le journal", "mapping ATT&CK traité dans REQ-17", "oui oui oui"),
("REQ-03", O, "Inventaire des 3 fiches binaires", "02-Artefacts/Inventaire-binaires.csv", V, "script", "9 empreintes retrouvées dans le CSV", "fiches seulement", "oui oui oui"),
("REQ-04", O, "Vérification des empreintes et analyse statique des 3 binaires", "04-Analyse/Analyse-binaires.md", BL, "Analyse-binaires.md : « analyse des fiches fournies »", "non exécutable", "échantillons non fournis (B-01)", "non non non"),
("REQ-05", O, "Intégrité et provenance", "02-Artefacts/Integrite-et-provenance.md", C, "21 constats, hachages", "hachages et comparaisons automatiques ; incohérences repérées à la main", "relecture humaine", "oui oui partiel"),
("REQ-06", O, "Registre des sources et journal de collecte", "03-Sources/", C, "10 sources, journal de collecte", "recoupement avec les actions réalisées", "aucune source d'enrichissement externe sur les IoC (volontaire)", "oui oui partiel"),
("REQ-07", O, "Note de cadrage de 2 pages (fin J1)", "01-Cadrage/Note-cadrage.pdf", C, "PDF 2 pages", "pagination mesurée", "**produite après l'échéance J1** ; équipe à confirmer", "oui oui oui"),
("REQ-08", O, "Planning 35 h", "01-Cadrage/Planning-35h.md", C, "tableau 35 h", "total vérifié", "prévisionnel, temps réel inconnu", "oui oui partiel"),
("REQ-09", O, "Rôles et communication", "01-Cadrage/Roles-et-communication.md", C, "modèle de rôles", "-", "titulaires à confirmer (B-05)", "partiel oui non"),
("REQ-10", O, "Analyse des IoC, alertes, binaires", "04-Analyse/Analyse-*.md", C, "matrice de 22 colonnes, 29 preuves relues", "relecture automatique des extraits", "analyse des IoC et des fiches non revue par un tiers", "oui oui partiel"),
("REQ-11", O, "Chronologie", "04-Analyse/Chronologie.csv", C, "34 événements triés", "tri vérifié", "dépend de HYP-001/002 (contradiction)", "oui oui partiel"),
("REQ-12", O, "Enrichissement par sources ouvertes tracé", "03-Sources/Journal-collecte.csv", C, "ATT&CK, ANSSI, CNIL, FIRST", "pages relues", "aucune source ouverte sur les valeurs d'IoC (décision : pas d'envoi à un tiers)", "partiel oui partiel"),
("REQ-13", O, "Événement MISP dédié ingéré", "05-Plateformes/Journal-ingestion.csv", V, "événement 6, 46 attributs, 5 objets, 8 galaxies ATT&CK, distribution « votre organisation seulement » ; capture 11-Validation/preuves-consultation/", "relecture API, requêtes SQL en lecture seule, **contrôle graphique de l'événement le 2026-10-06** (compte administrateur de l'utilisateur)", "étiquettes personnalisées non créées (droits d'éditeur) ; balise tlp:amber alors qu'OpenCTI est en TLP:RED (écart à arbitrer) ; objet file sans size-in-bytes (attribut libre)", "oui oui oui"),
("REQ-14", O, "Vérification MISP en lecture", "05-Plateformes/Verification-MISP.md", V, "sortie de relecture", "comparaison au manifeste, écarts listés", "contrôle graphique réalisé le 2026-10-06 (voir REQ-13)", "oui oui oui"),
("REQ-15", O, "Bundle STIX 2.1 d'au moins 25 objets liés", "06-STIX-Graphe/Bundle-STIX.json", C, "152 objets ; 27 objets de renseignement liés dans une même composante (méthode conservatrice) : Justification-25-objets-lies.md", "validateur 0 erreur ; comptage reproductible par script", "définition non confirmée par le commanditaire (RFI-05) ; bundle dérivé, pas un export MISP pur", "oui oui oui"),
("REQ-16", O, "Validation STIX (syntaxe et métier)", "06-STIX-Graphe/Rapport-validation-STIX.md", V, "sortie des validateurs archivée", "stix2-validator valide 0 erreur, parse, patterns, 548 références", "218 avertissements classés (82 identifiants UUIDv5 assumés, 117 propriétés de provenance x_helios_ assumées, 19 bonnes pratiques), pas de relecture par un pair", "oui oui oui"),
("REQ-17", O, "Matrice ATT&CK vérifiée sur source officielle", "04-Analyse/Matrice-ATTACK.csv", C, "17 techniques lues, T1685.005 vérifiée", "pages officielles ; version ATT&CK documentée (04-Analyse/Version-ATTACK.md)", "techniques des fiches non retenues faute de preuve ; correspondance v18.1 vérifiée pour T1070.001 seulement", "oui oui partiel"),
("REQ-18", O, "Diamond Model", "04-Analyse/Diamond-Model.md", C, "sommets et relations avec statuts", "-", "adversaire INCONNU", "oui oui non"),
("REQ-19", O, "Attribution et Admiralty", "04-Analyse/Hypotheses-et-attribution.md", C, "cluster non attribué, 5 hypothèses", "-", "aucune source indépendante", "oui oui non"),
("REQ-20", O, "Matrice CID", "04-Analyse/Matrice-risques-CID.csv / .pdf", C, "5 actifs, 3 colonnes d'impact", "-", "criticités conditionnelles (rôles déduits)", "oui oui non"),
("REQ-21", O, "Cartographie SI par méthode d'analyse de risques", "04-Analyse/Cartographie-SI.md", C, "actifs, flux, dépendances, inconnues", "-", "méthode inspirée d'EBIOS RM, non complète", "oui oui non"),
("REQ-22", O, "Au moins 10 règles Sigma fondées sur l'analyse", "07-Detection-Tests/sigma/", V, "15 règles (11 directes)", "syntaxe 15/15, tests 410 événements", "non déployables telles quelles sur de vrais journaux", "oui oui oui"),
("REQ-23", O, "Plan de tests et résultats", "07-Detection-Tests/Plan-tests.md", V, "162 + 180 lignes de résultats", "exécutions réelles archivées", "jeux synthétiques écrits par l'équipe ; aucun taux de faux positifs en production ; dashboard Wazuh contrôlé le 2026-10-06", "oui oui oui"),
("REQ-24", O, "Graphe CTI depuis le bundle, script de régénération", "06-STIX-Graphe/Graphe-CTI.png", V, "PNG, PDF, script", "régénéré depuis le bundle ; rendu relu", "filtre documenté", "oui oui oui"),
("REQ-25", O, "Rapport stratégique PDF 2 à 3 pages", "08-Rapports/Rapport-strategique.pdf", C, "PDF 2 pages", "pagination, cohérence chiffrée", "non relu par le commanditaire", "oui oui oui"),
("REQ-26", O, "Rapport tactique PDF 8 à 12 pages", "08-Rapports/Rapport-tactique.pdf", C, "PDF 11 pages", "pagination, tableaux générés depuis les CSV", "non relu par le commanditaire", "oui oui oui"),
("REQ-27", O, "Note d'attribution", "08-Rapports/Note-attribution.pdf", C, "PDF 2 pages", "-", "non relue", "oui oui non"),
("REQ-28", O, "Note ANSSI, 1 page", "08-Rapports/Note-reglementaire-ANSSI.pdf", C, "PDF 1 page, sources officielles du jour", "pagination", "OIV fourni par l'énoncé, SIIV et secteur inconnus ; NIS 2 à revérifier", "oui oui oui"),
("REQ-29", O, "Note de partage TLP, 1 page", "08-Rapports/Note-partage-communautaire.pdf", C, "PDF 1 page, TLP 2.0", "pagination", "glossaire du sujet non fourni", "oui oui oui"),
("REQ-30", O, "Journaux J1 à J5", "09-Journal-mission/", C, "5 journaux, dates réelles", "-", "temps et équipe non renseignés", "oui oui non"),
("REQ-31", O, "Soutenance : plan, support PDF, questions", "10-Soutenance/", C, "15 diapositives, 18 questions", "pagination, durée indicative 20 min", "non répétée", "oui oui partiel"),
("REQ-32", O, "Couverture des 8 compétences", "11-Validation/Couverture-competences.md", C, "tableau 8 lignes", "-", "aucune validation de formateur", "oui oui non"),
("REQ-33", O, "Manifeste des livrables avec hashes", "11-Validation/Manifest-livrables.csv", V, "généré par script", "hachages recalculés", "-", "oui oui oui"),
("REQ-34", O, "Contrôle final de cohérence", "11-Validation/Controle-final.md", C, "script de contrôle et sortie", "exécuté", "relecture humaine", "oui oui oui"),
("REQ-35", O, "Pilotage : tableau de bord, décisions et limites, infrastructure", "00-Pilotage/", C, "fichiers à jour", "recoupement", "-", "oui oui partiel"),
("REQ-36", O, "Dépôt Git local cti-helios-energy (exigence du sujet)", "~/Projet/cti-helios-energy (à créer)", E, "script 11-Validation/preparer-depot-git.sh (étapes preflight, copy, verify, init, commit) : preflight et essai à blanc exécutés (182 fichiers retenus, aucun secret ni binaire)", "simulation seulement : le dépôt n'existe pas", "**l'utilisateur crée le dépôt lui-même (décision du 2026-10-07)** ; commandes et vérification réelle dans Depot-Git-confirmation.md ; fourniture/ et captures inclus localement avec avertissement avant publication ; aucune publication distante", "partiel oui partiel"),
("SUP-01", S, "Mission consultable dans OpenCTI : Analyses, Événements, Observations", "05-Plateformes/Guide-consultation-OpenCTI.md", V, "47 objets étiquetés, 26 relations, 4 détections relus par API ; rapport, 28 entités, 4 données observées, 4 détections, 27 observables, 8 indicateurs, incident (20 entités, 8 indicateurs liés) vus dans l'interface, captures archivées", "relecture API + **contrôle graphique le 2026-10-06**", "réserves (voir Diagnostic-OpenCTI.md) : le graphe se consulte sur le RAPPORT (il s'affiche), pas sur l'incident ; onglet Indicateurs de l'incident vide car les 8 relations sont `related-to` (les 8 sont sous Entités liées) ; 3 organisations sans étiquette ni marquage ; PDF tactique joint = ancienne version (10 pages) ; libellés « VRAI POSITIF » et « 5 - Improbable » de la plateforme", "oui oui oui"),
("SUP-02", S, "Investigation OpenCTI consultable (/dashboard/workspaces/investigations)", "05-Plateformes/octi_investigation_rfi.py ; Relecture-investigation-rfi.json", V, "enquête créée le 2026-10-07 (approuvée) : 56 entités existantes et 30 relations existantes, persistante (relue par API), ouverte dans l'interface avec navigation et graphe (capture 11-Validation/preuves-consultation/opencti-investigation-graphe-vue-arbre.jpg)", "relue par API et dans l'interface (Chrome de l'utilisateur)", "**avec réserves** : licence Enterprise expirée (la rubrique fonctionne) ; libellés qui se chevauchent, vue en arbre la plus lisible, aucune mise en page enregistrée ; observables sans relation autre que leur indicateur affichés isolés ; aucun acteur", "oui oui oui"),
("SUP-03", S, "RFI OpenCTI consultables (/dashboard/cases/rfis)", "00-Pilotage/Suivi-RFI.md ; Relecture-investigation-rfi.json", V, "5 RFI créées le 2026-10-07 (approuvées), statut NEW, TLP:RED, sans assigné ni destinataire ni échéance ; liens vers 2 à 8 objets existants ; relues par API et dans l'interface (liste et fiche)", "relues par API et dans l'interface ; aucune notification externe constatée", "**les 5 RFI restent ouvertes, aucune réponse** : une RFI créée prouve un suivi, pas l'obtention de l'information", "oui oui oui"),
("OPT-01", P, "OpenCTI : correspondance MISP/OpenCTI", "05-Plateformes/Verification-OpenCTI.md", C, "connecteur MISP en marche mais sans interrogation de MISP, aucun filtre, isolation par organisation MISP", "journaux lus", "absence d'import à surveiller après vidage de la file", "partiel oui partiel"),
("OPT-02", P, "Cortex : analyses locales", "05-Plateformes/Verification-Cortex.md", NA, "-", "-", "analyseurs tiers ; aucune clé ; non exécuté par choix de sécurité", "non non non"),
("OPT-03", P, "Wazuh : rejeu isolé puis production (volet optionnel)", "07-Detection-Tests/wazuh/", V, "27 alertes générées et indexées", "logtest 45/45 x2, rejeu isolé et production, indexeur", "27 alertes vues dans le dashboard le 2026-10-06 ; règles de production à revoir ou retirer avant usage réel (retrait préparé, non exécuté)", "oui oui oui"),
("OPT-04", P, "CrowdSec", "-", NA, "-", "-", "aucune fonction pertinente démontrée", "non non non"),
("OPT-05", P, "Consultation dark web", "03-Sources/Darkweb-consultatif.md", V, "journal horodaté de 4 consultations de sources en clair (3 sources enregistrées), aucune interaction", "règles, méthode, journal et limites rédigés", "consultation indirecte par des sources en clair : aucun accès direct aux services .onion ; aucune valeur du dossier envoyée", "non non non"),
]
# --- Révision du 2026-10-06 (après exécution de controles-exigences.py) : critères du §14 du sujet = livrable existant, contenu attendu présent, preuve traçable, contrôle exécuté, limites explicites. La validation par le commanditaire est une colonne distincte.
import csv as _c
_ctl = collections.defaultdict(list)
for _r in _c.DictReader(open(os.path.join(B, "11-Validation", "Controles-exigences.csv"), encoding="utf-8")): _ctl[_r["exigence"]].append(_r["resultat"])
HUM = {"REQ-05": "oui : interprétation des 21 incohérences", "REQ-07": "oui : pertinence du cadrage", "REQ-09": "oui : titulaires et rôles à fournir par l'équipe", "REQ-10": "oui : jugement analytique des 12 alertes", "REQ-11": "oui : interprétation des contradictions",
       "REQ-15": "oui : arbitrage du mode de comptage (Q14)", "REQ-18": "oui : jugement sur les inconnues du losange", "REQ-19": "oui : jugement d'attribution et cotes Admiralty", "REQ-20": "oui : criticités", "REQ-21": "oui : méthode d'analyse de risques", "REQ-22": "oui : pertinence opérationnelle avant déploiement réel",
       "REQ-25": "oui : lisibilité pour la direction", "REQ-26": "oui : lecture technique par un analyste SOC", "REQ-27": "oui : argumentation", "REQ-28": "oui : relecture juridique avant tout usage réel", "REQ-29": "oui : politique de partage", "REQ-31": "oui : répétition orale", "REQ-32": "oui : jugement d'un formateur", "REQ-36": "non"}
PROMO = {  # id: (preuve, contrôle, limite)
 "REQ-05": ("sha256 des 7 originaux ; 21 constats I-01 à I-21", "hachages recalculés et comparés à l'inventaire, numérotation des constats, comptages séparés (4 contrôles OK)", "interprétation des incohérences non relue ; origine amont des fichiers inconnue (imputable au dossier)"),
 "REQ-06": ("registre de 21 sources, journal de 21 collectes", "champs obligatoires, cohérence registre/journal, sources officielles du jour ajoutées (3 contrôles OK)", "aucune source d'enrichissement sur les valeurs d'IoC (choix de sécurité) ; NIS 2 : sources secondaires seulement"),
 "REQ-07": ("PDF 2 pages", "pagination, sections attendues, remise tardive déclarée (3 contrôles OK)", "**produite après l'échéance J1** (déclaré) ; équipe à confirmer"),
 "REQ-08": ("tableau 35 h", "total 35 h et somme des lignes recalculés, caractère prévisionnel (3 contrôles OK)", "prévisionnel : temps réel inconnu (dossier)"),
 "REQ-09": ("modèle de rôles et de communication", "présence des sections, absence de noms inventés (2 contrôles OK)", "titulaires non communiqués (B-05) : imputable au dossier"),
 "REQ-10": ("matrice 12 x 22, 29 preuves relues", "12 alertes comparées aux originaux (horodatage, hôte, ligne de journal), 0 cellule vide, vocabulaire d'évidence (7 contrôles OK)", "jugement analytique non relu par un tiers"),
 "REQ-11": ("34 événements", "tri recalculé, colonnes exigées, 34 références artefact:ligne résolues dans les originaux (4 contrôles OK)", "dépend des contradictions HYP-001 et HYP-002"),
 "REQ-12": ("registre et journal de collecte, 8 sources officielles du jour", "sources ATT&CK, ANSSI, CNIL, FIRST, Légifrance tracées ; aucun envoi à un tiers (2 contrôles OK)", "aucune source ouverte sur les valeurs d'IoC (décision documentée)"),
 "REQ-17": ("matrice 18 lignes, Correspondance-ATTACK-v18-v19.csv, Version-ATTACK.md", "18 techniques + T1070.001 vérifiées par script contre les bundles officiels v18.1, v19.0 et v19.2 (6 contrôles OK)", "statut observée/probable lié aux artefacts : jugement ; descriptions des pages non comparées entre versions"),
 "REQ-18": ("modèle de Diamond avec statuts", "4 sommets, relations connues et inconnues, identifiants cités existants (4 contrôles OK)", "adversaire inconnu (imputable au dossier)"),
 "REQ-19": ("cluster non attribué, 5 hypothèses HYP-A1 à A5, Admiralty séparée", "hypothèses comparées, contradictions, indépendance des sources, biais, aucun acteur nommé (5 contrôles OK)", "aucune source indépendante (imputable au dossier) ; cotes Admiralty de l'équipe non relues"),
 "REQ-20": ("5 actifs, observé / potentiel / futur", "colonnes exigées, criticité justifiée, actifs rattachés aux hôtes des alertes (3 contrôles OK)", "criticités conditionnelles (rôles déduits)"),
 "REQ-21": ("actifs, flux, dépendances, inconnues", "sections exigées présentes (2 contrôles OK)", "méthode inspirée d'EBIOS RM, non complète ; pas d'atelier métier"),
 "REQ-25": ("PDF 2 pages", "pagination, 7 rubriques exigées (2 contrôles OK)", "non relu par la direction"),
 "REQ-26": ("PDF 11 pages", "pagination 8 à 12, 12 rubriques, 15 règles référencées, chiffres cités, aucune mention périmée (5 contrôles OK)", "non relu par un analyste SOC"),
 "REQ-27": ("PDF 2 pages", "pagination, 6 rubriques exigées (2 contrôles OK)", "argumentation non relue"),
 "REQ-28": ("PDF 1 page ; ANSSI, CNIL, Légifrance L1332-6-2 relus le 2026-10-06", "pagination, distinctions OIV/SIIV/sectoriel, NIS 2 et RGPD non appliqués automatiquement, aucune déclaration réelle (4 contrôles OK)", "NIS 2 : sources secondaires ; OIV fourni par l'énoncé, SIIV et secteur non fournis (dossier) ; relecture juridique avant usage réel"),
 "REQ-29": ("PDF 1 page, TLP 2.0 (FIRST)", "pagination, version TLP, catégories, marquages réels (3 contrôles OK)", "glossaire du sujet non fourni"),
 "REQ-30": ("5 journaux J1 à J5 complétés", "sections exigées dans chaque journal, dates réelles (7 contrôles OK)", "temps et équipe non renseignés (imputable au dossier)"),
 "REQ-31": ("support 15 diapositives, 18 questions, plan", "pagination, nombre de questions, 20 + 10 min, thèmes de défense (4 contrôles OK)", "non répétée"),
 "REQ-32": ("tableau de 8 compétences", "8 lignes complètes, fichiers cités existants, aucune économie revendiquée sans mesure (3 contrôles OK)", "aucune validation de formateur"),
 "REQ-34": ("controle-coherence.py et sa sortie", "script relancé après les corrections : 0 écart", "un script de contrôle se contrôle lui-même ; complété par controles-exigences.py"),
 "REQ-35": ("tableau de bord, matrice, décisions et limites, infrastructure", "présence et cohérence chiffrée avec la matrice (6 contrôles OK)", "contenu non relu par l'utilisateur"),
}
_rows = []
for r in rows:
    r = list(r)
    if r[0] in PROMO and r[4] != V:
        r[4] = V; r[5], r[6], r[7] = PROMO[r[0]]; r[8] = "oui oui oui"
    _rows.append(r)
rows = _rows
# Statuts finaux : surcharges explicites (statut, limite précise). Rien n'est promu à SATISFAIT pour atteindre un pourcentage.
FINAL = {
 "REQ-04": (BL, "échantillons des 3 binaires non fournis (preuve : `fourniture/` ne contient que les fiches, le LISEZ-MOI le dit) ; aucune empreinte recalculée, aucune analyse statique ; RFI-01 ouverte"),
 "REQ-07": (C, "note de 2 pages produite et à jour, mais **après l'échéance « fin J1 »** (aucune journée réelle n'a séparé les phases) : critère de délai non satisfait ; équipe non communiquée"),
 "REQ-15": (V, "**27 objets de renseignement liés** dans une même composante (campagne, 3 malwares, 3 outils, 4 infrastructures, 8 techniques, 8 indicateurs), 25 sans les 2 ajouts fondés sur le texte d'une alerte seulement : méthode conservatrice de l'équipe, **définition non confirmée par le commanditaire** (RFI-05 ouverte) ; statuts des objets : observé 13, déclaré 7, hypothèse 6 ; bundle dérivé de l'export MISP, ajouts absents de MISP"),
 "REQ-36": (E, "dépôt `cti-helios-energy` **non créé** : sa création n'a pas été approuvée le 2026-10-07 ; procédure complète prête (`preparer-depot-git.sh`) ; un essai à blanc ne vaut pas création"),
 "SUP-01": (V if os.path.exists(os.path.join(B, "05-Plateformes", "Remplacement-PDF-joints.json")) else C, "mission présente et relue dans Analyses (1 rapport de 103 objets), Événements (incident 1, données observées 4, détections 4) et Observations (27 observables, 8 indicateurs, 4 infrastructures) ; pièces jointes remplacées par les versions Markdown des rapports le 2026-10-10 (approuvé ; PDF finaux du 07/10 archivés) ; **limite** : onglet Indicateurs de l'incident vide (relations `related-to` maintenues par choix, les 8 indicateurs se lisent dans « Entités liées »)"),
 "SUP-02": (C, "enquête en **vue synthétique** (39 éléments, 43 relations existantes, mise en page par colonnes enregistrée, navigation vers les objets, sauvegarde persistante relue) ; **limites** : la mise en page ne s'affiche qu'avec les forces désactivées (`&withForces=false`), libellés petits au zoom d'ensemble, notes non dessinées par l'interface, hypothèses distinguées par étiquette et description seulement, licence Enterprise expirée"),
 "SUP-03": (V, "5 RFI créées, relues par API et interface, ouvertes (NEW) sans réponse : l'information manquante reste une limite finale (voir `Decisions-et-limites-finales.md`)"),
 "OPT-01": (C, "correspondance MISP/OpenCTI contrôlée par valeur (`Ecarts-bundle-plateformes.md`, 12 écarts classés) ; **aucune synchronisation par connecteur** (connecteur non repris) : correspondance démontrée par comparaison, pas par flux"),
 "OPT-02": (NA, "Cortex : aucun job pour la mission (journal d'accès 2026-09-19 à 2026-10-07, 0 lancement du 01 au 07/10) ; analyseurs tiers non approuvés ; voir `Verification-Cortex.md`"),
 "OPT-04": (NA, "CrowdSec : aucune fonction pertinente démontrée pour la mission (aucun blocage, aucune réponse active)"),
 "OPT-05": (V, "dark web : consultation **indirecte** par des sources en clair (catalogue de sources, suivi de sites de fuite, fiche FIN7), 4 consultations horodatées, aucune interaction, aucun achat, aucune valeur du dossier envoyée ; **pas d'accès direct aux services .onion** ; voir `03-Sources/Darkweb-consultatif.md`"),
}
for r in rows:
    if r[0] in FINAL: r[4], r[7] = FINAL[r[0]]
H0 = None
H = ["id", "categorie", "exigence", "livrable_attendu", "statut", "preuve", "controle_execute", "manque_ou_limite", "declare_realise", "preuve_archivee", "controle_execute_niveau", "valide", "relu_par_commanditaire", "controles_techniques", "relecture_humaine_necessaire"]
with open(os.path.join(B, "00-Pilotage", "Matrice-exigences.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(H)
    for r in rows:
        fl = r[8].split()
        _k = _ctl.get(r[0], []); w.writerow(list(r[:8]) + fl + ["oui" if r[4] == V else "non", "non", (f"{_k.count(chr(79)+chr(75))}/{len(_k)} OK" if _k else "voir preuve"), HUM.get(r[0], "non")])
for cat in (O, S, P):
    sub = [r for r in rows if r[1] == cat]
    c = collections.Counter(r[4] for r in sub)
    print(f"{cat[:28]:28} total {len(sub):2} | " + " ; ".join(f"{k} {v}" for k, v in c.items()) + f" | couverture VALIDÉE {c[V]}/{len(sub)} ({100*c[V]/len(sub):.1f} %)")
