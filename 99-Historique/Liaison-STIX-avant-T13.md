# Objets STIX « liés » : comptage reproductible

Généré par `06-STIX-Graphe/generer-liaison-stix.py` depuis `Bundle-STIX.json` (133 objets). Inventaire ligne à ligne : `Inventaire-liaison-STIX.csv` (identifiant, type, provenance, références entrantes et sortantes, relations explicites, composante connexe, inclusion dans chaque définition, justification).

## Pourquoi 34, 24 et 20 (et 99)

| Définition | Ce qui est compté | Résultat | ≥ 25 ? |
|---|---|---|---|
| **C, conservatrice** | objets analytiques (indicateur, malware, campagne, technique) extrémités d'au moins une relation explicite (SRO) | **20** | **non** |
| B | C et les identités (victime et 3 hôtes) | **24** | non |
| A | tout objet (hors relation) extrémité d'une relation : 24 de B, plus 5 observables et 5 données observées | **34** | oui |
| D | A, plus tout objet référencé par un conteneur (rapport, regroupement, note) ou une donnée observée | **99** | oui |

**Définition retenue pour le contrôle : C** (la plus prudente : un objet « lié » est un objet d'analyse relié par une relation explicite, pas un observable ni un conteneur). **Cette définition n'a pas été acceptée par le commanditaire** : elle est mon choix conservateur, documenté. Résultat : **25 n'est pas démontré** sous C ni sous B. Il l'est sous A et D, définitions plus larges (un observable relié à un indicateur compte comme « lié »).

Composantes connexes (relations seules) : {"1": 2, "2": 32} : un seul graphe de 32 objets autour de la campagne, plus une paire isolée ; les deux identités d'auteur et le marquage n'ont aucune relation.

## Ajouts justifiés proposés (non appliqués)

`Ajouts-STIX-proposes.json` prépare 4 objets `infrastructure` (rôles tirés des alertes 2, 4, 10 et 11, qui décrivent déjà téléchargement, balise, sortie et repli) avec 8 relations (`uses` depuis la campagne, `consists-of` vers les observables existants). Chacun a une justification dans les artefacts ; le rôle de repli est étiqueté HYPOTHÈSE (contradiction I-11). Effet simulé : A = 38, B = 28, C = 24.
**Même avec ces ajouts, C reste à 24, sous 25.** Aucun autre objet justifié par les artefacts n'a été trouvé : les 32 IoC non retenus comme indicateurs sont volontairement hors bundle (IOC-025 et 026 non diffusables, hash non vérifiables, techniques « probables » sans preuve). Créer des objets pour atteindre 25 serait du bourrage de quota, donc **rien n'est créé**. Décision demandée : RFI-05 (définition de « objets liés ») et, après arbitrage seulement, approbation des ajouts.

## Verdict pour REQ-15

Bundle valide (0 erreur, voir `Rapport-validation-STIX.md`). Seuil de 25 : **démontré sous les définitions A et D, non démontré sous B et C**. REQ-15 reste **PARTIEL** : la définition relève du commanditaire.
