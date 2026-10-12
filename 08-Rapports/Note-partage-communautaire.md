# Note de partage communautaire et TLP (1 page)

**Rien n'a été publié ni partagé hors de l'infrastructure de l'utilisateur.** Rédigée le 2026-10-06.

## 1. Version de TLP en vigueur

Le site de FIRST indique le **TLP version 2.0** (en vigueur depuis août 2022) avec **cinq** étiquettes : **TLP:RED**, **TLP:AMBER+STRICT**, **TLP:AMBER**, **TLP:GREEN**, **TLP:CLEAR**. **TLP:WHITE n'existe plus** (remplacé par TLP:CLEAR). Source : [FIRST, Traffic Light Protocol](https://www.first.org/tlp/), consultée le 2026-10-06.

**Écart possible avec le glossaire du sujet** (non fourni dans le dossier : limite) : un glossaire fondé sur TLP 1.0 emploierait TLP:WHITE et ignorerait AMBER+STRICT. Équivalences utilisées ici : WHITE donne CLEAR ; AMBER (v2) = organisation et clients en besoin d'en connaître ; AMBER+STRICT = organisation seule. Le mémo du SOC porte « TLP:AMBER, diffusion interne restreinte » : la mention « interne restreinte » correspond en v2 à **AMBER+STRICT**, pas à AMBER.

## 2. Classement des catégories d'information

| Catégorie | Contenu | TLP proposé | Justification |
|---|---|---|---|
| Indicateurs réseau et hashes (après validation) | domaines, IP, empreintes | **GREEN** (communauté) | utiles à la défense collective ; ici fictifs et non vérifiés : **rien à partager** en pratique |
| Règles de détection (Sigma) | 15 règles | **GREEN** après relecture | génériques ; les règles IOC et de chasse sont à retirer du partage |
| Identité de la victime, noms d'hôtes, comptes | Helios, comptabilite-07, svc-backup-temp… | **AMBER+STRICT** | identifie l'organisation et sa topologie |
| Analyse technique détaillée (rapport tactique) | chronologie, preuves, limites | **AMBER** | utile au SOC et à un CERT sectoriel de confiance |
| Rapport stratégique | impacts, décisions | **AMBER+STRICT** | direction seule |
| Journaux bruts et pièces du dossier | `fourniture/` | **RED** | contiennent des éléments internes ; jamais copiés dans les plateformes |
| Attribution | conclusion « non attribué » | **AMBER** | hypothèses et limites à ne pas diffuser comme faits |

## 3. Ce qui reste interne et pourquoi

Tout, dans cet exercice : victime fictive, indicateurs fictifs, limites fortes (aucun échantillon, aucune source indépendante). Partager des indicateurs non vérifiés produirait du bruit dans la communauté. Un partage réel exigerait : validation des indicateurs, accord de la direction, anonymisation de la victime.

## 4. Marquages réellement posés dans les plateformes (et leur sens)

| Plateforme | Marquage | Sens |
|---|---|---|
| MISP | `tlp:amber`, distribution 0, non publié, organisation dédiée | classement d'échange ; l'isolation vient de l'**organisation propriétaire** et de la distribution, **pas** du TLP |
| OpenCTI | `TLP:RED` sur tous les objets | **garde technique d'enrichissement** : les connecteurs d'enrichissement automatiques ne traitent que les objets dont le TLP est inférieur ou égal à leur maximum (IPinfo : AMBER). Ce n'est **pas** un classement de partage et **pas** une isolation |
| Wazuh | groupe `helios_challenge`, niveaux 4 à 7 | traçabilité ; les niveaux restent sous les seuils d'automatisation |

Un label ou un TLP n'est jamais présenté ici comme une isolation technique.
