# Note d'attribution : INC-2026-0302

Date : 2026-10-06. **Conclusion : cluster non attribué.** Analyse complète : `04-Analyse/Hypotheses-et-attribution.md`.

## 1. Question

Les artefacts permettent-ils de relier l'intrusion à un groupe, un acteur ou une famille d'outils nommés ?

## 2. Réponse argumentée

**Non.** Aucune observation du lot n'est spécifique à un acteur ; il n'existe aucune source indépendante ; l'unique rapprochement d'outillage est une affirmation de fiche, non vérifiable et explicitement « à valider ».

## 3. Preuves favorables à un rapprochement

- La fiche BIN-02 indique que le format de balise et une gigue de 20 % recoupent des descriptions publiques d'outils cybercriminels (famille apparentée à Carbanak/FIN7). Statut : DÉCLARÉ.
- La chaîne hameçonnage, PowerShell, tâche planifiée, identifiants, sortie de données est compatible avec une finalité lucrative. Statut : COMPATIBLE, non discriminant.

## 4. Preuves contradictoires ou limites

- Une **seule** ligne de balise : l'intervalle de 300 s et la gigue ne sont **pas mesurables** dans le journal, donc l'argument central de la fiche n'est pas vérifiable.
- Les descriptions publiques invoquées ne sont pas fournies ; aucun échantillon (pas de comparaison de code).
- L'outil LSASS est « très largement partagé » selon la fiche elle-même.
- Aucune phase de rançongiciel, aucune donnée financière ciblée dans le dossier.
- Les deux pivots externes (IOC-028, IOC-035) renvoient à des sources absentes.
- Le LISEZ-MOI du dossier pédagogique contient une piste annoncée : **indication, pas preuve** ; elle répète la fiche (même chaîne d'information).

## 5. Alternatives examinées

| Hypothèse | Verdict |
|---|---|
| Cluster cybercriminel à outillage recoupant une famille connue | faible, non démontrée |
| Opérateur opportuniste, outils du marché | compatible, peu informative |
| Acteur étatique | non soutenue, **non exclue** (aucun indice de sabotage, d'accès OT, de discrétion prolongée ; sortie en clair peu discrète) |
| Jeu de données synthétique | certain pour le cadre (plages RFC 5737, domaines .test) |
| Initié | non testée, non soutenue |

## 6. Cotation Admiralty (séparée de la confiance)

| Élément | Source (A à F) | Information (1 à 6) | Commentaire |
|---|---|---|---|
| Rapprochement d'outillage (fiche BIN-02) | C | 4 (douteuse) | non vérifiable, non indépendante |
| Piste du LISEZ-MOI | D (pédagogique, répète la fiche) | 5 si prise comme preuve | écartée de la chaîne de preuve |
| IOC-028, IOC-035 | C | 6 (ne peut être jugée) | sources externes absentes |
| Enchaînement technique observé | C | 3 (possiblement vraie) | une seule ligne par étape |

Ces cotes ne sont ni des probabilités ni des niveaux de confiance.

## 7. Niveau de confiance de la conclusion

- « Aucun acteur nommé ne peut être établi » : **élevée**.
- « Finalité lucrative » : **faible**, hypothèse non discriminante (la même chaîne, accès, identifiants, sortie de données, sert aussi l'espionnage) ; aucune demande ni donnée financière observée.
- « Rapprochement d'outillage avec une famille connue » : **faible**.

## 8. Biais et parades

Confirmation (piste annoncée), notoriété (noms connus), sélection (artefacts choisis par le fournisseur), ancrage sectoriel (énergie, donc acteur d'État ?). Parades : analyse partie des observations ; aucune galaxie ou relation d'acteur dans MISP, OpenCTI ni STIX ; absence de preuve non assimilée à preuve d'absence.

## 9. Ce qui permettrait d'aller plus loin

Échantillons et configuration de la balise, journaux de balise complets, certificat TLS et passive DNS, source du RDP, contenu de la sortie, sources indépendantes pour IOC-028 et IOC-035.
