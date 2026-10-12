# Analyse des fiches binaires fournies

**Intitulé exact : analyse des fiches fournies.** Les échantillons n'ont pas été fournis (limite définitive B-01, RFI-01 ouverte). Je n'ai **ni recalculé** les empreintes, **ni exécuté**, **ni désassemblé** quoi que ce soit. Tout ce qui suit est la lecture critique de `fourniture/01_fiches_analyse_binaires.md` rapprochée des alertes et du journal.

## 1. Ce que les fiches affirment, et ce que les artefacts permettent d'en dire

| BIN | Affirmation de la fiche | Corroboration dans le dossier | Statut | Confiance | Limite |
|---|---|---|---|---|---|
| BIN-001 `facture_mars_2026.xlsm`, 68242 octets | Macro VBA qui déchiffre une charge base64 et lance PowerShell masqué ; écrit une clé Run | ALERT-001 montre powershell.exe -enc (préfixe décodé : IEX) -w hidden ; **parent winword.exe alors que le fichier est un .xlsm** | PowerShell encodé : OBSERVÉ ; macro, clé Run : DÉCLARÉ | moyenne pour l'exécution PowerShell, faible pour le lien au fichier | I-18 ; commande tronquée ; aucun code VBA fourni |
| BIN-002 `svchost_update.exe`, 421376 octets, PE 64 bits empaqueté | Hollowing dans explorer.exe, tâche planifiée, balise toutes les 300 s ± 20 %, HTTPS | Taille concorde avec la réponse Squid (journal l.2) ; tâche créée (l.3) ; **une seule** connexion de balise (l.4) ; injection par CreateRemoteThread (l.7), pas par hollowing | Téléchargement : OBSERVÉ/CORROBORÉ ; tâche : OBSERVÉ (action inconnue) ; périodicité et gigue : NON DÉMONTRÉES ; hollowing : NON DÉMONTRÉ | moyenne (téléchargement), faible (capacités) | Hash non recalculable ; la fiche elle-même est ambiguë sur le hollowing (explorer.exe existant) |
| BIN-003 `rundll32_helper.dll`, 210944 octets, DLL 64 bits | Lecture mémoire de LSASS ; fichier chiffré dans Windows\Temp ; service créé puis supprimé | Accès LSASS 0x1010 par « rundll32_helper.dll » (l.8) ; compte créé et supprimé (l.9, mais compte et non service) ; sortie de 2,47 Go (l.10) | Accès LSASS : OBSERVÉ ; service Windows : NON DÉMONTRÉ (aucun événement 7045/4697) ; staging : DÉCLARÉ | moyenne pour l'accès, faible pour le reste | L'outil est « très largement partagé » selon la fiche elle-même : aucune attribution |

## 2. Capacité supposée et comportement observé

| Capacité | Statut |
|---|---|
| Exécution de PowerShell encodé depuis Office | comportement OBSERVÉ (une ligne) |
| Téléchargement d'un exécutable de 421376 octets | comportement OBSERVÉ |
| Persistance par tâche planifiée | création OBSERVÉE ; usage comme persistance : HYPOTHÈSE |
| Persistance par clé Run (IOC-038) | DÉCLARÉE ; valeur tronquée, aucune alerte |
| Injection dans explorer.exe | indice d'injection par thread distant OBSERVÉ ; sous-technique INCONNUE ; auteur INCONNU |
| Balisage HTTPS toutes les 300 s | **capacité supposée** : une connexion observée, l'intervalle n'est pas mesurable |
| Chiffrement du canal | DÉCLARÉ (fiche) ; le journal montre le port 443, pas le contenu |
| Extraction d'identifiants (LSASS) | accès mémoire OBSERVÉ ; extraction effective NON DÉMONTRÉE |
| Staging chiffré avant exfiltration | DÉCLARÉ (IOC-012, 039) ; sortie de volume OBSERVÉE |

## 3. Techniques ATT&CK citées par les fiches

Les techniques des fiches ne sont pas reprises telles quelles. Seules celles qui reposent sur un artefact d'observation figurent dans `Matrice-ATTACK.csv` (voir statuts). Non démontrées : T1566.001, T1204.002 (courriel et ouverture : aucun journal), T1059.005 (VBA), T1573 (chiffrement), T1074.001 (staging), T1543.003 (service), T1055.012 (hollowing).

## 4. Ce qu'il faudrait pour aller plus loin

Les échantillons en environnement isolé (analyse statique : type, imports, chaînes, packer ; recalcul des empreintes) ; les journaux Sysmon complets ; les horodatages de la tâche et de la clé Run ; la configuration de la balise. Aucune analyse dynamique n'a été proposée ni exécutée.
