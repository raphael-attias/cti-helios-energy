# Diagnostic OpenCTI : graphe, onglet Indicateurs, liens réels, PDF joints

Date : 2026-10-06. Méthodes : consultation de l'interface dans le Chrome de l'utilisateur (comptes déjà connectés), lecture GraphQL depuis hiboux (lecture seule), console du navigateur. **Aucune relation n'a été créée ni modifiée.** Captures dans `11-Validation/preuves-consultation/`.

## 1. Pourquoi le graphe de l'incident ne se rendait pas

| Hypothèse | Test | Résultat |
|---|---|---|
| Page servie en HTTP non sécurisé (`crypto.randomUUID` indisponible) | `window.isSecureContext` = false, `crypto.randomUUID` = undefined (constat vrai) ; rendu du graphe **du rapport** sur la même page sans correctif | **écartée** : le graphe du rapport s'affiche sans correctif (3 canevas) |
| Erreur JavaScript de la page | console du navigateur | une seule erreur, venant d'une extension du navigateur (`crypto.randomUUID is not a function` dans le script de l'extension), sans lien avec OpenCTI |
| Problème de données ou de WebGL | WebGL disponible ; 20 relations lues par API et par la vue « relations » de l'interface | **écartée** |
| **L'écran n'existe pas pour un incident dans cette version** | sur la page de l'incident, la barre de la connaissance n'offre que : liste, vue des relations, export ; aucun bouton de graphe ; l'adresse `/knowledge/graph` tapée à la main reste vide | **cause retenue** |

Conclusion : le « graphe de l'incident » du guide de consultation **n'existe pas** dans OpenCTI 6.9.21 ; c'était une erreur du guide, pas un défaut des données. **Le graphe de connaissance est disponible sur le rapport** : `/dashboard/analyses/reports/3ec91c0f-915b-4e1d-9cd9-c1c12c79f342/knowledge/graph` (ou l'onglet « Connaissance » du rapport). Il s'affiche et montre l'incident, les 8 techniques, les systèmes, les indicateurs et les observables (capture `opencti-rapport-graphe-connaissance.jpg`). Le guide de consultation est corrigé.

## 2. Pourquoi l'onglet « Indicateurs » de l'incident affiche zéro

Le schéma d'OpenCTI n'autorise, entre un indicateur et un incident, que la relation **`indicates`** (lecture du schéma : `Indicator_Incident` = `indicates`). L'onglet « Indicateurs » du panneau de droite liste seulement ces relations. Les 8 indicateurs sont reliés à l'incident par **`related-to`**, relation générique acceptée mais non listée par l'onglet. Le compteur « 8 » du panneau compte toutes les relations ; la liste « Entités liées » montre bien les 8 indicateurs (capture `opencti-incident-entites-liees-8-indicateurs.jpg`).

Ce n'est pas un défaut de données : c'est un choix de type de relation fait à l'ingestion.

## 3. Liens qui existent réellement (lus par API)

| Lien | Type | Nombre | Remarque |
|---|---|---|---|
| Rapport contient objets | conteneur (pas une relation STIX) | 103 objets (85 à l'origine, puis 18 ajoutés le 2026-10-07 : 4 infrastructures, 1 outil créé, 2 outils MITRE reliés, 11 relations) dont au départ : 8 techniques, 1 incident, 8 indicateurs, 27 observables (10 IPv4, 7 fichiers, 5 URL, 3 certificats, 1 compte, 1 dossier), 4 données observées, 3 notes, 3 systèmes, 1 organisation, plus 30 relations | le rapport n'a lui-même **aucune** relation STIX |
| Incident vers techniques | `uses` | 8 | techniques = entités minimales d'AlienVault (nom = identifiant), plus T1685.005 officielle |
| Incident vers systèmes et organisation victime | `targets` | 4 (3 systèmes, 1 organisation) | |
| Indicateur vers incident | `related-to` | 8 | voir 2 |
| Indicateur vers observable | `based-on` | 6 | IND-04 et IND-08 portent sur des noms de domaine, **non créés comme observables** (garde Google DNS) : pas de `based-on` |
| Détections (sightings) | indicateur vers système | 4 | IND-04, 06, 07, 08 |
| Données observées | contiennent un observable chacune (IPv4 198.51.100.24, URL cdn-svc-update, IPv4 203.0.113.28, URL static-assets-cache) | 4 | **aucune relation directe** avec l'incident ni avec les indicateurs ; elles ne sont liées que par le rapport |
| Incident vers observables | aucune | 0 | l'écran « Connaissance » de l'incident affiche « Nombre d'observables : 0 » : exact |

Aucune relation n'est ajoutée pour remplir un onglet. Ne pas relier directement les données observées à l'incident : OpenCTI ne définit pas de relation standard utile ici et ce serait inventer un lien non démontré.

## 4. Corrections : état final

| # | Correction | Effet | Risque / réserve |
|---|---|---|---|
| C1 | Remplacer les 8 relations `related-to` indicateur vers incident par `indicates` | l'onglet Indicateurs listerait les 8 | **non appliquée, décision de ne pas la prendre** : `indicates` affirmerait que ces indicateurs signalent l'incident, or ils restent des hypothèses de confiance 15 à 50 ; les 8 se lisent dans « Entités liées » |
| C2 | Corriger le guide de consultation (graphe sur le rapport, onglet Indicateurs vide expliqué) | local | **fait** |
| C3 | Remplacer les pièces jointes PDF du rapport (tactique de 10 pages, stratégique antérieur) par les versions finales | cohérence plateforme et livrable | **non approuvé le 2026-10-07** : limite assumée, les versions finales sont dans `08-Rapports/` |
| C4 | Marquage et étiquette des 3 organisations | filtre de retrait complet | **fait le 2026-10-07 après approbation** (voir `Classification-et-validite.md`) |

## 5. PDF joints

État relu le 2026-10-07 : onglet « Données » du rapport : 2 fichiers téléversés, `Rapport-tactique.pdf` (813 014 octets) et `Rapport-strategique.pdf` (110 835 octets), tous deux marqués TLP:RED. **Le PDF stratégique s'ouvre dans l'interface (2 pages, texte lisible)** ; **le PDF tactique s'ouvre (10 pages) mais c'est l'ancienne version** : le livrable local fait désormais 11 pages (voir C3). Aucun import automatique n'a été déclenché (aucune nouvelle entité créée par ces fichiers).
