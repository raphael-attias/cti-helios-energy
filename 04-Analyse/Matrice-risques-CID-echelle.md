# Échelle et lecture de la matrice CID

Fichier de données : `Matrice-risques-CID.csv`. Une ligne par actif **réellement identifié comme touché** : comptabilite-07, srv-fichiers-02, dc-01, le volume de données sorti, le compte svc-backup-temp. Aucun annuaire compromis, serveur industriel ou exfiltration de données sensibles n'est affirmé : ils ne sont pas démontrés.

| Note | Signification (impact) |
|---|---|
| 0 | Aucun impact démontré par les artefacts |
| 1 | Faible : gêne limitée, récupérable sans conséquence métier |
| 2 | Modéré : atteinte d'un composant, remise en état nécessaire |
| 3 | Élevé : atteinte sérieuse de données ou d'un service important |
| 4 | Critique : atteinte systémique ou de données hautement sensibles |

Criticité de l'actif (1 à 4) : fonction (rôle documenté ou déduit), étendue de dépendance, sensibilité probable des données. Elle est **justifiée ligne par ligne** et reste conditionnelle lorsque le rôle est déduit d'un nom d'hôte.

Trois colonnes distinctes : **impact observé** (démontré par un artefact), **impact potentiel** (ce que l'accès observé permettrait), **risque futur** (scénario, non quantifié). Une note observée de 0 signifie « non démontré », jamais « absent ».
