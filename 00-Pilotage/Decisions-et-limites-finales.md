# Décisions et limites finales

Registre de clôture, au 2026-10-07. Il remplace, pour la lecture du dossier final, les registres de questions (`Q1` à `Q32`) et de blocages (`B-01` à `B-23`), conservés dans `99-Historique/`. Chaque élément y est devenu l'une de quatre choses : **décision prise**, **résolution effectuée**, **limitation définitive**, ou **arbitrage non obtenu** (avec sa conséquence). Les décisions techniques numérotées DEC-001 à DEC-037 restent dans `Journal-decisions.md`. Aucune réponse du commanditaire n'est supposée : tout ce qui relève de lui et qu'il n'a pas donné est écrit comme tel.

## 1. Décisions prises

| Réf. | Sujet | Décision |
|---|---|---|
| Q3, B-03 | Isolation dans MISP | événement non publié, distribution 0, organisation propriétaire dédiée ; visibilité vérifiée avec le compte du connecteur (ne voit pas l'événement) |
| Q12, B-07 | Enrichissement ouvert | seulement des sources officielles sans valeur d'IoC (ATT&CK, ANSSI, CNIL, FIRST, Légifrance) ; aucun service de réputation, aucun envoi d'IoC à un tiers |
| Q18 | Dépôt Git | emplacement `/Users/rapatt/Projet/cti-helios-energy`, local, sans remote (voir §3) |
| Q19 | Méthode d'analyse de risques | inspirée d'EBIOS RM, simplifiée, assumée comme non complète |
| Q20, B-12 | Écriture OpenCTI | production avec garde-fous (TLP:RED, indicateurs expirés, aucun domaine, aucun label du filtre Jira) |
| Q22, Q27, B-15 | Compte d'écriture OpenCTI | jeton d'administration de la plateforme (aucun compte restreint) ; limite assumée |
| Q23 | Dates de l'incident | bornes d'observation (2026-03-02T08:31Z, 2026-03-07T09:02Z) avec avertissement : ce ne sont ni un début ni une fin certains |
| Q24 | Comptages publiés | publiés avec leurs définitions ; non validés par le commanditaire |
| B-11 | Statut OIV | fourni par l'énoncé et retenu ; SIIV et secteur restent inconnus |
| DEC-037 | « Objets liés » | contrôle sous la définition conservatrice (20 objets analytiques), documentée dans `06-STIX-Graphe/Justification-25-objets-lies.md` |

## 2. Résolutions effectuées

| Réf. | Sujet | Résolution |
|---|---|---|
| Q1, B-02 | Accès MISP | utilisateur dédié créé par la commande applicative de l'hôte ; clé jamais affichée, fichier supprimé |
| Q2, B-13, B-14, Q21 | Connecteurs et flux OpenCTI | configurations lues ; aucun connecteur désactivé ; objets conçus pour ne rien déclencher ; contrôles du 2026-10-07 dans `Controle-live-2026-10-07.md` |
| Q4, B-04 | Outils locaux | venv dédié hors du dossier de mission |
| Q17, B-06 | Périmètre de test Wazuh | conteneur isolé sans réseau, puis déploiement ciblé en production (groupe `helios_challenge`) |
| Q25, B-16 | Contrôle des interfaces | MISP, OpenCTI et Wazuh contrôlés dans l'interface les 06 et 07/10 (captures dans `11-Validation/preuves-consultation/`) |
| Q30 | Marquage des 3 organisations | **fait le 2026-10-07 après approbation** : étiquette `challenge:helios-fictif` et TLP:RED, relu par API |
| RFI, SUP-02 | Investigation et RFI OpenCTI | créées le 2026-10-07 après approbation (`Suivi-RFI.md`) ; enquête en vue synthétique (`Investigation-OpenCTI-finale.md`) |
| C3, E10 | Pièces jointes PDF du rapport OpenCTI | **remplacées par les versions finales le 2026-10-07 après approbation** ; anciennes versions archivées (`99-Historique/pieces-jointes-opencti-avant-remplacement/`) |
| E12 | Outils et infrastructures du bundle absents d'OpenCTI | 4 `Infrastructure`, 1 `Tool` et 11 relations créés le 2026-10-07 après approbation ; ajoutés au rapport |
| RFI-05 | Texte de la RFI-05 périmé | mis à jour le 2026-10-07 après approbation (`octi_rfi05_maj.py`) |
| TheHive, Cortex | Usage | vérifiés en lecture seule : **ni l'un ni l'autre n'a été utilisé** (`Verification-TheHive.md`, `Verification-Cortex.md`) |

## 3. Arbitrages non obtenus, avec leur conséquence

| Réf. | Ce qui manque | Conséquence retenue |
|---|---|---|
| Q31, B-09, B-23 | Création du dépôt Git `cti-helios-energy` : soumise à approbation le 2026-10-07 (trois fois), **non approuvée** | dépôt **non créé** ; REQ-36 NON SATISFAIT ; la procédure complète est prête et vérifiée à blanc (`preparer-depot-git.sh`, `Depot-Git-confirmation.md`) |
| Q14, B-08 | Définition de « au moins 25 objets liés » (jamais fournie ; RFI-05 ouverte) | REQ-15 **satisfait sous la méthode conservatrice de l'équipe** : 27 objets de renseignement (25 sans 2 ajouts fondés sur le texte d'une alerte) reliés dans une même composante ; 7 objets prouvés par les artefacts ajoutés le 2026-10-07 ; le commanditaire peut exiger une définition plus stricte (par exemple les seuls objets « observé », 13) : le statut serait alors à revoir |
| Q15, B-10 | Confirmation de la liste des 36 exigences (sujet officiel absent du dossier) | dénominateur de 36 conservé (lecture du brief et dépôt obligatoire) ; réserve écrite dans `Exigences-origine.md` |
| Q26 | Maintien ou retrait des objets pédagogiques | **maintien de fait** ; procédures de retrait préparées (`Options-restes-production.md`). Conséquence : les règles Wazuh 130101 à 130115 restent actives sur de vrais événements (niveaux 4 à 7, sous les seuils d'intégration) |
| Q28 | Filtre et reprise du connecteur MISP vers OpenCTI | connecteur ni repris ni filtré ; conséquence : aucune synchronisation, l'événement 6 reste invisible du compte du connecteur |
| Q29, B-21 | Niveau TLP commun | MISP en `tlp:amber` (`tlp:red` n'existe pas et sa création demande un administrateur), OpenCTI en TLP:RED ; l'isolation réelle de MISP est sa diffusion 0, le TLP n'est qu'une étiquette de traitement |
| Q32 | `valid_from` des indicateurs | 8 indicateurs OpenCTI gardent la date uniforme du 2026-03-02 08:30Z, le bundle porte la date de la première alerte (écart E2 documenté) ; indicateurs expirés et révoqués, sans effet sur la détection |
| C1 | Relation indicateur vers incident | restent `related-to` : `indicates` affirmerait un lien que des hypothèses de confiance 15 à 50 ne soutiennent pas ; l'onglet Indicateurs de l'incident reste vide, les 8 indicateurs se lisent dans « Entités liées » |
| E3, B-22 | `first_seen` des attributs d'objets MISP | demande un compte administrateur : non obtenu ; l'écart est neutralisé dans le bundle local (transformation T12) |

## 4. Limitations définitives

| Réf. | Limitation | Origine |
|---|---|---|
| Q5, B-01, RFI-01 | **Aucun échantillon binaire** : les 3 fiches sont analysées en tant que fiches ; aucune empreinte recalculée, aucune analyse statique | dossier fourni ; REQ-04 NON SATISFAIT |
| Q6, Q7, Q8, Q9, Q10, RFI-02 | 6 incohérences non levées : date du mémo, compte utilisé avant sa création, correspondance des identifiants des fiches, parent `winword.exe`, nature de 198.51.100.55 et source du RDP, repli connu avant usage | dossier fourni ; hypothèses HYP-001 et HYP-002 maintenues ouvertes, IoC 25 et 26 non diffusables comme offensifs |
| Q11, RFI-04 | Une seule ligne de balise ; journaux complets, supports de pivot et rapport public cité absents ; aucune source indépendante : **cluster non attribué** | dossier fourni |
| Q13, B-05 | Équipe, rôles, temps réels non communiqués | rien n'est inventé ; titulaires « non communiqués » |
| Q16, RFI-03 | SIIV, secteur réglementaire et contenu des 2 469 135 790 octets sortis inconnus | dossier fourni ; criticités CID conditionnelles, notes ANSSI conditionnelles |
| B-17 | Rôle Publisher de MISP : pas d'étiquette personnalisée, pas d'édition d'attributs d'objets | droits |
| B-18 | ATT&CK v19 non reflété dans la galaxie MISP (v18.1), la base MITRE de Wazuh et certaines entités OpenCTI (entités minimales AlienVault) | méthode retenue : v19.2 avec correspondance v18.1 |
| B-19 | Règles Wazuh non validées sur de vrais journaux Windows ; aucun taux de faux positifs de production ; jeux de test synthétiques | périmètre de la mission |
| B-12, B-15 | OpenCTI : pas d'isolation technique ni de partage par organisation (licence d'essai expirée) ; marquages et étiquettes sont de la traçabilité | plateforme |
| — | Playbooks OpenCTI illisibles par l'API ; effets sur des événements Wazuh entrants pendant le redémarrage de 41 s non mesurés ; comportement futur de l'organisation MISP insérée en SQL non testé | plateforme et méthode (`Insertion-organisation-MISP.md`) |
| — | Textes présents dans les plateformes et non modifiés (écriture non demandée) : mention de composition d'équipe non renseignée dans l'organisation « Équipe CTI » d'OpenCTI, titre « Synthèse provisoire » du rapport d'événement MISP | écriture non demandée |
| SUP-02 | Investigation : mise en page enregistrée visible seulement forces désactivées, libellés petits au zoom d'ensemble, 3 notes non dessinées | plateforme (`Investigation-OpenCTI-finale.md` §7) |
| REQ-15 | Les ajouts T13 existent dans le bundle et OpenCTI, pas dans MISP (aucun type équivalent) ; les 3 malwares des fiches ne sont pas dans OpenCTI | modèle des plateformes (E12) |
| — | Aucune relecture par un tiers ; aucune validation du commanditaire ; sujet officiel et glossaire TLP absents ; NIS 2 vérifié sur des sources secondaires | périmètre |
