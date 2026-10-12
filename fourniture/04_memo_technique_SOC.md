# Mémo technique initial — SOC Helios Energy
Classification : TLP:AMBER — diffusion interne restreinte
Rédigé le 2026-03-02T10:30:00Z par l'équipe SOC de garde
Référence incident : INC-2026-0302

## Contexte
Le 2 mars 2026, un utilisateur du service comptabilité signale un classeur Excel reçu
par courriel qui « ouvre une fenêtre noire puis disparaît ». Le poste concerné
est comptabilite-07. Le SOC ouvre l'incident dans l'heure.

## Ce que nous savons à ce stade
- Le classeur (BIN-01) contient une macro qui lance PowerShell et télécharge
  une seconde charge (BIN-02) depuis un domaine externe jamais vu chez nous.
- BIN-02 s'installe durablement (tâche planifiée) et communique régulièrement
  avec un serveur externe.
- Trois jours plus tard, une alerte critique remonte sur le contrôleur de
  domaine dc-01 : accès à la mémoire LSASS, puis création d'un compte de
  service éphémère. Nous soupçonnons un vol d'identifiants suivi d'un
  déplacement vers les serveurs de fichiers.
- Un volume sortant anormal (plusieurs gigaoctets) a été observé vers une
  adresse externe le quatrième jour.

## Ce que nous ne savons pas
- L'étendue exacte des données exfiltrées.
- Si l'attaquant est toujours présent.
- Qui est derrière l'attaque. Nous n'avons pas fait d'attribution : c'est
  précisément le travail attendu de la cellule CTI.

## Ce que nous vous remettons
- 40 indicateurs de compromission collectés pendant l'incident (fichier CSV/JSON).
- 12 alertes SIEM correspondant à la chronologie ci-dessus.
- 3 fiches d'analyse de binaires (les échantillons ne sont pas diffusés).
- Ce mémo.

## Attentes
Reconstituer la chaîne d'attaque, cartographier les techniques sur MITRE ATT&CK,
tenter une attribution argumentée avec un niveau de confiance, et produire les
rapports et notes réglementaires demandés dans le sujet.

Rappel : Helios Energy est la victime. Ne cherchez pas d'informations « sur
Helios Energy » à l'extérieur : partez de ces artefacts et remontez vers
l'attaquant.
