# Registre des blocages et questions

Mis à jour le 2026-10-06 (phase 1 puis analyse des alertes). Liste priorisée des questions : `Questions-commanditaire.md`. Les questions marquées **réponse requise** empêchent d'avancer sur la phase indiquée.

| ID | Sujet | Détail | Impact | Réponse requise |
|---|---|---|---|---|
| B-01 | Binaires non fournis | Le dossier `fourniture/` contient 3 **fiches** d'analyse (`01_fiches_analyse_binaires.md`), pas 3 échantillons. Le LISEZ-MOI le confirme : « les échantillons ne sont pas fournis ». | Vérification des empreintes par recalcul et analyse statique impossibles (REQ-04). Les empreintes ne sont que **déclarées**. | Confirmer que les fiches tiennent lieu de « 3 binaires » et que REQ-04 est à traiter comme limite documentée. |
| B-02 | Accès MISP et Cortex | Aucune clé API MISP ou Cortex n'a été trouvée dans les emplacements prévus pour ce travail. Je n'ai pas fouillé les fichiers de configuration d'autres projets pour en chercher. | Aucune lecture authentifiée de MISP, aucune ingestion. | Quel compte MISP utiliser (de préférence dédié au challenge, rôle sans droit de publication) et comment me transmettre la clé sans qu'elle apparaisse dans un rapport. Même question pour Cortex si utilisé. |
| B-03 | Synchronisations de production | MISP alimente OpenCTI (30 min) et TheHive (1 h) d'après la documentation du vault. | Des IoC fictifs peuvent entrer dans le graphe de production et dans les connecteurs de détection. | Choisir : (a) instance ou organisation MISP isolée, (b) événement en distribution « cette organisation seulement », non publié, `to_ids=false`, avec vérification préalable de la configuration du connecteur, (c) pas d'ingestion MISP. Recommandation : (b) **uniquement si** la lecture de la configuration des connecteurs prouve qu'un événement non publié, en distribution 0, n'est pas importé. La distribution « organisation seule » n'est **pas** considérée comme une isolation garantie avant cette vérification (question Q2). |
| B-04 | Outils locaux manquants | `stix2`, validateur STIX, `pymisp`, `pysigma`, `matplotlib`, `networkx` absents ; moteur PDF non testé. | STIX, Sigma, graphe et PDF non réalisables en l'état. | Accord pour créer un venv dédié (`cti-helios-energy/.venv`) et y installer ces paquets depuis PyPI. Aucune modification du Python système. |
| B-05 | Équipe, dates, temps | Aucun membre d'équipe, aucune date de travail antérieure, aucun temps passé communiqué. | Rôles, planning réel et temps des journaux J1 à J5 restent vides ; je n'invente rien. | Noms et rôles (2 ou 3 personnes), dates réelles d'exécution, temps passé si connu. |
| B-06 | Périmètre de test Wazuh | Le volet optionnel exige un périmètre isolé. Le vault mentionne un laboratoire (`lab-victim`, Kali) sur le VLAN 11, sans filtrage fort vis-à-vis du reste. L'API Wazuh (55000) n'est pas joignable depuis le Mac. | Volet optionnel non démarrable. | Désigner un agent/une VM de test et l'accès, ou renoncer au volet. |
| B-07 | Enrichissement externe | Les 40 IoC sont des plages de documentation (RFC 5737) et des domaines `.test` : aucune donnée publique attendue. Interroger un service tiers revient à lui transmettre ces valeurs. | Enrichissement open source probablement vide ; la méthode reste à démontrer. | Autoriser ou non des requêtes tierces (par exemple documentation officielle MITRE : autorisé par nature, car aucune valeur d'IoC n'est envoyée ; services de réputation : à refuser par défaut). |
| B-08 | Mode de comptage STIX | « Au moins 25 objets liés » : comptage des objets de domaine seuls, ou aussi des relations et marquages ? | Définit le bundle minimal. | Choix du commanditaire ; à défaut, je compte **séparément** les quatre catégories et je vise 25 hors relations. |
| B-09 | Dépôt Git `cti-helios-energy` | Non créé. | **Obligatoire dans le sujet (REQ-36), non optionnel.** | Emplacement proposé : `~/Projet/cti-helios-energy/` (local, privé, sans binaire ni secret, sans remote). À valider. |
| B-10 | Sujet d'origine | Le sujet officiel n'est pas dans le dossier ; je n'ai que votre prompt et le LISEZ-MOI. La distinction obligatoire/optionnel de la matrice est **ma lecture** du prompt. | Dénominateur de couverture potentiellement contestable. | Confirmer la liste des exigences obligatoires (`Matrice-exigences.csv`). |
| B-11 | Statut réglementaire fictif | **Le statut OIV d'Helios Energy est fourni par l'énoncé** (« opérateur d'importance vitale ») : donnée d'entrée, pas une information absente. Restent inconnus : les SIIV concernés et l'arrêté sectoriel. | La note ANSSI traite l'OIV comme acquis et le SIIV comme hypothèse explicite. | Seulement : préciser SIIV et secteur si le commanditaire les connaît (Q16). |
| B-12 | Écriture OpenCTI : isolation | OpenCTI de production (6.9.21, Communauté, licence d'essai expirée) sans isolation technique disponible : labels, marquages et auteurs ne sont que de la traçabilité. | Aucune écriture possible sans choix d'option (A instance locale jetable, B production avec garde-fous, C Brouillon). | Q20 |
| B-13 | Enrichissement automatique tiers | Connecteurs Google DNS et IPinfo en mode automatique : la création d'observables domaine ou IPv4 peut transmettre des valeurs à un service externe. Portée et TLP maximal non lus. | Écriture en production bloquée tant que non neutralisé ou levé. | Q21 |
| B-14 | Flux Jira public | Flux live `jira` public avec connecteur « Atlassian JIRA » actif, filtres non lus : création d'un incident ou d'un rapport potentiellement relayée vers Jira. | Idem. | Q21 |
| B-15 | Droits d'écriture OpenCTI non testés ; session = compte administrateur principal | Aucun test d'écriture ; droits du jeton MCP inconnus. | Compte dédié à définir. | Q22 |
| B-16 | Interface OpenCTI non contrôlable après ingestion sans accès navigateur | Le contrôle de l'interface s'est fait via le Chrome de l'utilisateur déjà connecté ; à reconduire après écriture, ou sur l'option A. | Formulation « API seule » sinon. | Q20 |

## Mise à jour de fin de session (2026-10-06)

| ID | Statut final | Détail |
|---|---|---|
| B-01 | **OUVERT** | échantillons toujours absents ; REQ-04 bloquée |
| B-02 | **RÉSOLU** | voie locale : utilisateur MISP dédié créé via la CLI de l'hôte ; clé jamais affichée ; Cortex non utilisé |
| B-03 | **TRAITÉ** | isolation par organisation propriétaire et distribution 0 ; connecteur MISP vers OpenCTI en pause et sans filtre : surveillance restante |
| B-04 | **RÉSOLU** | venv dédié installé hors du vault ; schémas STIX liés ; PDF par Chrome local |
| B-05 | **OUVERT** | équipe, rôles, temps réels non communiqués |
| B-06 | **RÉSOLU** | périmètre de test : conteneur isolé puis déploiement ciblé en production (groupe helios_challenge) |
| B-07 | **TRAITÉ** | sources officielles consultées sans transmettre d'IoC |
| B-08 | **OUVERT** | mode de comptage des 25 objets STIX |
| B-09 | **OUVERT** | dépôt Git obligatoire non créé ; script prêt, essai à blanc fait ; création par l'utilisateur |
| B-10 | **OUVERT** | confirmation des exigences officielles |
| B-11 | **RECLASSÉ (2026-10-07)** | statut OIV fourni par l'énoncé, non traité comme absent ; SIIV et secteur restent inconnus, sans effet sur la validité des livrables |
| B-12 à B-14 | **TRAITÉS** | écriture OpenCTI après garde-fous (TLP:RED, aucun domaine, label Jira non utilisé, indicateurs expirés) ; aucun connecteur désactivé |
| B-15 | **OUVERT (limite)** | écriture avec le jeton d'administration de la plateforme (aucun compte restreint) |
| B-16 | **TRAITÉ** | contrôle graphique réalisé le 2026-10-06 (MISP, OpenCTI, Wazuh) ; le graphe se consulte sur le rapport (il n'existe pas sur l'incident) ; voir `05-Plateformes/Diagnostic-OpenCTI.md` |
| B-17 | **OUVERT** | MISP : étiquettes personnalisées et tailles dans les objets non obtenues (droits Publisher) |
| B-18 | **OUVERT** | (v19 publiée le 28 avril 2026, v18.1 en vigueur lors de l'incident) ATT&CK v19 non reflété dans MISP (galaxie), Wazuh (base MITRE) et certaines entités OpenCTI (stubs AlienVault) |
| B-19 | **OUVERT** | décodeurs et règles de production Wazuh à revoir pour de vrais journaux Windows ; retrait des 2 fichiers sur demande |
| B-20 | **OUVERT** | pièce jointe `Rapport-tactique.pdf` d'OpenCTI = ancienne version (10 pages) ; version locale de 11 pages (correction C3, approbation requise) |
| B-21 | **OUVERT** | tag MISP `tlp:red` inexistant (seuls `tlp:amber` et `tlp:clear`) : l'alignement TLP MISP/OpenCTI demande une action d'administrateur (Q29) |
| B-22 | **OUVERT** | `first_seen` absent des attributs d'objets MISP : un nouvel export reproduit la date d'ingestion (corrigée dans le bundle local par T12) |
| B-23 | **OUVERT** | dépôt Git : l'utilisateur le crée lui-même (commandes dans `Depot-Git-confirmation.md`) ; vérification réelle ensuite |
