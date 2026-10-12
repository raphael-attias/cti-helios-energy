# Fiches d'analyse des binaires — Incident Helios Energy

> Ces fiches remplacent les échantillons eux-mêmes. Elles reprennent ce qu'un
> bac à sable d'analyse fournit : empreintes, type, comportement observé,
> techniques repérées. Aucun binaire exécutable n'est distribué.

## BIN-01 — facture_mars_2026.xlsm

- **Origine** : Pièce jointe d'un courriel signalé par un utilisateur du service comptabilité le J0.
- **SHA-256** : `2d10d13c3f3a045dc12a48e0a484018c053d0e83c607f2796fc9b8307c0d66e5`
- **SHA-1** : `4911bfb2fa8f76909de149299ef05e6b1455ea24`
- **MD5** : `8ba35251cca8daa4a05331bba8f95b05`
- **Taille** : 68242 octets
- **Type** : Document Office avec macro VBA
- **Première apparition** : 2026-03-02T08:30:00Z
- **Verdict** : Malveillant — dropper

**Comportement observé**

- À l'ouverture, la macro VBA déchiffre une charge encodée en base64 et lance PowerShell en fenêtre masquée.
- PowerShell télécharge une seconde charge depuis un domaine externe (voir BIN-02).
- Écrit une valeur dans HKCU\Software\Microsoft\Windows\CurrentVersion\Run.

**Techniques (MITRE ATT&CK)**

- T1566.001 Spearphishing Attachment
- T1059.001 PowerShell
- T1204.002 Malicious File

**Éléments liés** : le domaine de téléchargement D-01, l'empreinte de la charge PowerShell

**Note d'analyse** : La macro contient des commentaires en anglais et une chaîne de version « build 7.3 » réutilisée dans BIN-02 : indice d'un même outilleur.

---

## BIN-02 — svchost_update.exe

- **Origine** : Charge téléchargée par BIN-01, récupérée sur le poste comptabilité-07.
- **SHA-256** : `cdf03e90d85977619f7881a13f59a275812dbf0e4ae29874493728b0ef78ebc9`
- **SHA-1** : `ca91f74f2438d710e130a5a413b2c75219c9d5a9`
- **MD5** : `91678506a5474354f1ceb4c12c3c56dd`
- **Taille** : 421376 octets
- **Type** : Exécutable Windows PE 64 bits, empaqueté (UPX modifié)
- **Première apparition** : 2026-03-02T08:41:00Z
- **Verdict** : Malveillant — balise de commande et contrôle

**Comportement observé**

- Injecte son code dans un processus légitime (explorer.exe) par creux de processus.
- Établit une persistance par tâche planifiée nommée « MicrosoftEdgeUpdateTaskMachine ».
- Contacte un serveur de commande toutes les 300 secondes, en HTTPS, avec un intervalle aléatoire de +/- 20 %.
- Balise contenant nom de machine, utilisateur, privilèges.

**Techniques (MITRE ATT&CK)**

- T1055.012 Process Hollowing
- T1053.005 Scheduled Task
- T1071.001 Web Protocols
- T1573 Encrypted Channel

**Éléments liés** : les serveurs de commande IP-07 et IP-08, le domaine D-02, le certificat CERT-01

**Note d'analyse** : Le format de balise et le jitter de 20 % recoupent des descriptions publiques d'outils employés par des groupes cybercriminels (famille apparentée à Carbanak/FIN7). À valider, ne pas conclure sur ce seul élément.

---

## BIN-03 — rundll32_helper.dll

- **Origine** : Récupéré sur le contrôleur de domaine après mouvement latéral, J3.
- **SHA-256** : `f4109cd2860816d568c5581edf8ed5df28d35471fa8ff849e9ee2451b69135f0`
- **SHA-1** : `d1a4a3501bd1b1d9bc32ade2b4add3cb135e36b8`
- **MD5** : `3435016f3f2aacce36b71abb636cfc64`
- **Taille** : 210944 octets
- **Type** : Bibliothèque Windows PE 64 bits
- **Première apparition** : 2026-03-05T14:05:00Z
- **Verdict** : Malveillant — outil de collecte d'identifiants

**Comportement observé**

- Accède à la mémoire du processus d'autorité de sécurité locale (LSASS) pour en extraire des identifiants.
- Écrit un fichier chiffré dans C:\Windows\Temp avant exfiltration.
- Utilise un service Windows créé à la volée puis supprimé.

**Techniques (MITRE ATT&CK)**

- T1003.001 LSASS Memory
- T1543.003 Windows Service
- T1074.001 Local Data Staging

**Éléments liés** : le fichier de collecte HASH-STAGE, l'IP d'exfiltration IP-09

**Note d'analyse** : Outil générique d'extraction d'identifiants. Ne permet pas à lui seul une attribution : très largement partagé.

---

