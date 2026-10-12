# Indication d'attribution du dossier pédagogique (consignée séparément)

Date : 2026-10-06. **Ce document n'est pas une preuve et n'alimente aucune conclusion.**

## 1. Ce que le dossier indique

Le fichier `fourniture/00_LISEZ-MOI.md` (ART-001) contient une section « Piste d'attribution » qui oriente vers un cluster cybercriminel à recouvrement partiel avec des outils de type FIN7/Carbanak, une phase de rançongiciel possible, et qui annonce la « bonne réponse attendue » (cluster non formellement attribué, confiance moyenne, pas d'acteur étatique). Statut retenu : **indication du dossier pédagogique, origine pédagogique, non-preuve** (DEC-004).

## 2. Ce que je ne fais pas

- Je ne reprends ni la conclusion ni le niveau de confiance annoncés.
- Je n'ajoute aucune galaxie d'acteur dans MISP.
- Je n'oriente pas la recherche d'enrichissement vers les noms cités.

## 3. Ce que l'analyse indépendante montre à ce stade

| Élément | Statut vérifié |
|---|---|
| Fiche BIN-02 : format de balise et gigue de 20 % « recoupent des descriptions publiques » d'outils cybercriminels, « à valider, ne pas conclure sur ce seul élément » | Déclaration de la fiche. Les descriptions publiques ne sont pas fournies. Le journal ne contient qu'**une** connexion de balise : ni l'intervalle de 300 s ni la gigue ne sont vérifiables dans les artefacts (ALERT-004). |
| Fiche BIN-03 : outil d'extraction d'identifiants « très largement partagé » | La fiche exclut elle-même toute attribution par cet outil. |
| Techniques observées : PowerShell encodé, tâche planifiée, accès LSASS, RDP, injection par thread distant, effacement de journaux | Techniques courantes et partagées par de nombreux acteurs ; aucune n'est discriminante seule. |
| IOC-028 (IP citée par un rapport public) et IOC-035 (certificat pivot vers janvier 2026) | Cotés D4 et C4 par le SOC, non vérifiables, sources non fournies. |
| Phase de rançongiciel | Aucun artefact de chiffrement ni de demande de rançon dans le lot. Non observée. |

**Position indépendante : INCONNU.** Aucun élément vérifiable des alertes et du journal brut ne permet de départager des acteurs. L'attribution (J3) partira de zéro, sur observations.

## 4. Hypothèses à tester (J3), sans préjuger du résultat

| ID | Hypothèse | Critère qui la ferait avancer ou reculer |
|---|---|---|
| HYP-A1 | Cluster cybercriminel dont les outils recoupent une famille connue | Similarité de code ou de format vérifiée sur échantillon, infrastructure partagée démontrée (pas la simple cooccurrence) |
| HYP-A2 | Affilié ou opérateur opportuniste réutilisant des outils du marché | Absence de spécificité, outils génériques, pas de signature opérationnelle |
| HYP-A3 | Acteur étatique | Aucun élément à ce stade ; exigerait des preuves indépendantes multiples |
| HYP-A4 | Données synthétiques sans acteur réel identifiable | Plages de documentation et domaines `.test` : le cadre pédagogique est certain, donc l'exercice porte sur la méthode |

Biais à surveiller : biais de confirmation (la piste annoncée), biais de notoriété (FIN7 est un nom connu), biais de sélection (fiches choisies par le fournisseur). Les sources qui se recopient (fiche BIN-02 et indice du LISEZ-MOI) ne comptent pas comme deux sources indépendantes.
