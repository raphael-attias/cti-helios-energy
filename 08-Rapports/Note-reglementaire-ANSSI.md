# Note réglementaire : notification d'incident (1 page)

**Victime fictive : aucune déclaration réelle n'est faite ni préparée pour l'envoi.** Rédigée le 2026-10-06 ; textes et pages officielles à **revérifier à la date de toute utilisation réelle**.

| Régime | S'applique à Helios si… | Ce que disent les sources consultées | Statut pour ce dossier |
|---|---|---|---|
| **OIV / SIIV** (Code de la défense, art. L1332-6-2) | l'incident affecte un système d'information d'importance vitale (SIIV) ; **le statut OIV d'Helios est fourni par l'énoncé** | Notification **« sans délai »** : l'article L1332-6-2 (en vigueur depuis le 2013-12-20, lu sur Légifrance) vise le Premier ministre, et la page ANSSI « Notifications réglementaires » indique l'ANSSI comme destinataire opérationnel ; formulaire papier ou en ligne ; les types d'incidents sont précisés par arrêtés sectoriels | Statut OIV : **fourni par l'énoncé du sujet** (donnée d'entrée du scénario, retenue telle quelle). Qualification SIIV et arrêté sectoriel : **INCONNUS** (non fournis). Obligation : applicable si un SIIV est touché, ce qui n'est pas établi |
| **NIS 2** | transposition en droit français achevée et entité dans le champ | La page ANSSI (contenu du 2026-03-17) renvoie à un « projet de loi Résilience » non encore adopté ; sources secondaires : examen à l'Assemblée annoncé à partir du 7 octobre 2026 | **Aucun délai NIS 2 n'est applicable en l'état** ; ne pas importer 24 h / 72 h dans le régime OIV. État ultérieur non revérifié sur Légifrance (limite) |
| **RGPD** (art. 33) | une **violation de données personnelles** est établie avec un risque pour les personnes | Notification à la CNIL **dans les 72 h** après en avoir pris connaissance, en une ou plusieurs étapes (page CNIL) | **Non déclenchée en l'état** : le contenu des 2,47 Go est inconnu ; la date de « prise de connaissance » n'est pas fixée |
| **Règles sectorielles (énergie)** | l'entité relève d'un arrêté sectoriel | Les obligations OIV sont déclinées par secteur | **Aucun secteur réglementaire précis n'est inventé** : à déterminer avec l'autorité compétente |

## Pour chaque notification possible

| Élément | OIV / ANSSI (CERT-FR) | RGPD / CNIL |
|---|---|---|
| Destinataire | ANSSI | CNIL |
| Délai | sans délai (pas de nombre d'heures fixé par la page consultée) | 72 h après prise de connaissance, complément possible |
| Canal | formulaire de déclaration (papier ou en ligne, plateforme de l'ANSSI) | téléservice de notification de violation |
| Contenu minimal | type d'incident, systèmes affectés (la page n'en liste pas davantage) | nature de la violation, catégories et nombre approximatif de personnes et d'enregistrements, conséquences probables, contact DPO, mesures prises |
| Pièces utiles issues du dossier | chronologie (bornes d'observation), hôtes touchés, volume sorti | idem, après qualification des données |

## Incertitudes et décisions préalables

1. **Qui qualifie** les SIIV concernés et le moment de « prise de connaissance » (le statut OIV étant fourni) ? Décision relevant de la direction et du responsable sécurité d'Helios, hors périmètre de la mission.
2. Les données exfiltrées contiennent-elles des données personnelles ? Tant que c'est inconnu, le délai RGPD ne peut ni être écarté ni constaté.
3. La loi de transposition de NIS 2 sera-t-elle en vigueur à la date de l'incident réel ? Revérification obligatoire.
4. Les dates du dossier sont des bornes d'observation (mémo daté avant les faits) : l'heure de départ du délai est donc **incertaine**.

Sources : [ANSSI, notifications réglementaires](https://cyber.gouv.fr/notifications-reglementaires) ; [ANSSI, directive NIS 2](https://cyber.gouv.fr/la-directive-nis-2) ; [CNIL, notifier une violation](https://www.cnil.fr/fr/services-en-ligne/notifier-une-violation-de-donnees-personnelles) ; [Légifrance, article L1332-6-2](https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000028342867). Consultées le 2026-10-06.
