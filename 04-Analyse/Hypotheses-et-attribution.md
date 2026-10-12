# Hypothèses et attribution

Date : 2026-10-06. **Conclusion : cluster non attribué.** Aucun groupe, acteur ou famille n'est retenu. La note rédigée pour la direction est `08-Rapports/Note-attribution.md`.

## 1. Point de départ : observations, pas noms

| ID | Observation | Preuve | Discriminante ? |
|---|---|---|---|
| OBS-001 | PowerShell encodé et masqué lancé par un processus Office | journal l.1 | Non : technique très courante |
| OBS-002 | Téléchargement d'un exécutable de 421376 octets | journal l.2, fiche | Non |
| OBS-003 | Tâche planifiée à nom d'imitation d'Edge | journal l.3 | Peu : imitation fréquente |
| OBS-004 | Une connexion en 443 étiquetée balise | journal l.4 | Non : une seule ligne |
| OBS-005 à 008 | Balayage 445/3389, RDP par compte de service, thread distant dans explorer.exe, accès LSASS | journal l.5 à 8 | Non |
| OBS-009 à 012 | Compte temporaire, sortie de 2,47 Go en clair sur 8080, repli, effacement de journal | journal l.9 à 12 | Non |

**Aucune observation n'est spécifique à un acteur.** La fiche BIN-03 indique elle-même que l'outil est « très largement partagé ».

## 2. Hypothèses comparées

| ID | Hypothèse | Soutien | Contradictions et manques | Statut |
|---|---|---|---|---|
| HYP-A1 | Cluster cybercriminel dont l'outillage recoupe une famille connue | Fiche BIN-02 : format de balise et gigue de 20 % « recoupent des descriptions publiques » ; chaîne hameçonnage, PowerShell, identifiants, exfiltration, compatible avec une finalité lucrative (compatible aussi avec d'autres finalités) | La fiche dit « à valider, ne pas conclure sur ce seul élément » ; descriptions publiques non fournies ; l'intervalle de 300 s et la gigue ne sont pas mesurables (une seule ligne de balise) ; aucun échantillon ; aucune phase de rançongiciel ; aucune donnée financière ciblée | HYPOTHÈSE faible, non démontrée |
| HYP-A2 | Opérateur opportuniste avec outils du marché | Compatible avec toutes les observations ; outil LSASS générique | Non réfutable donc peu informative | HYPOTHÈSE compatible |
| HYP-A3 | Acteur étatique | Aucun | Secteur énergétique évoqué par le sujet (contexte), aucun artefact de sabotage, d'OT ou de persistance furtive longue ; exfiltration en clair sur 8080, peu discrète | **NON SOUTENUE** |
| HYP-A4 | Jeu de données synthétique sans acteur réel | Plages RFC 5737 et .test, domaines non résolvables | Sans objet pour la méthode | CERTAIN pour le cadre pédagogique |
| HYP-A5 | Initié (insider) | Aucun | RDP depuis une source inconnue ; aucun élément RH | NON TESTÉ, non soutenue |

## 3. Indépendance des sources

| Élément | Origine | Indépendant ? |
|---|---|---|
| Fiche BIN-02 : « recoupe des descriptions publiques » | SOC (même fournisseur) | Non |
| LISEZ-MOI : piste d'attribution | Dossier pédagogique, répète la fiche | **Non : même chaîne** (consigné comme indication, `Indication-dossier-pedagogique.md`) |
| IOC-028 (rapport public), IOC-035 (campagne de janvier) | SOC, sources externes absentes | Non vérifiables |
| MISP, OpenCTI | 0 corrélation ou entité préexistante | Aucun recoupement externe |

Il n'existe donc **aucune source indépendante** au sens strict dans le lot.

## 4. Outil, infrastructure, lien d'acteur : trois niveaux à ne pas confondre

- **Outil partagé** : BIN-03 (extraction LSASS), PowerShell, RDP : usage répandu, pas d'identification.
- **Infrastructure partagée** : certificat et passive DNS « partagés » (IOC-016, 027, 033) : DÉCLARÉS, sans artefact. Non exploitables.
- **Lien d'acteur** : jamais observé.

## 5. Biais surveillés

| Biais | Où il aurait pu jouer | Parade |
|---|---|---|
| Confirmation | Piste annoncée dans le LISEZ-MOI | Consignée à part ; analyse partie des observations |
| Notoriété | Nom FIN7/Carbanak cité dans la fiche | Aucune recherche orientée ; aucune galaxie d'acteur dans MISP ; aucune relation vers un acteur dans OpenCTI ni STIX |
| Sélection | Les fiches et alertes sont choisies par le fournisseur | Limites écrites ; absence de preuve ≠ preuve d'absence (journal Security de comptabilite-07 effacé) |
| Ancrage sectoriel | « Opérateur d'importance vitale » suggère un acteur d'État | HYP-A3 évaluée sur artefacts seulement |

## 6. Niveau de confiance (argumenté, hors Admiralty)

| Énoncé | Confiance | Argument |
|---|---|---|
| « Aucun acteur nommé ne peut être établi sur les artefacts » | **élevée** | Aucune observation discriminante, aucune source indépendante |
| « Activité à finalité lucrative (accès, identifiants, exfiltration) » | **faible** | Cohérent avec la chaîne observée mais non discriminant (la même chaîne sert l'espionnage) ; motivation non observée |
| « Rapprochement d'outillage avec une famille connue » | **faible** | Une affirmation de fiche, non vérifiable |
| « Acteur étatique » | **très faible** | Aucun indice |

Cote Admiralty de l'énoncé de rapprochement d'outillage (fiche BIN-02) : **C4** (source de fiabilité moyenne, information douteuse car non vérifiée et non indépendante). Ce n'est pas une probabilité.

## 7. Ce qui changerait la conclusion

Les échantillons (similarité de code, configuration de balise), les journaux de balise complets (intervalle, gigue), le certificat TLS et le passive DNS, la source RDP, les données exfiltrées, et toute source indépendante sur IOC-028 et IOC-035.
