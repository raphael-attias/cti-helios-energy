# Dossier d'artefacts — Challenge CTI Helios Energy

Ce dossier est la matière de départ de l'investigation. Tout votre raisonnement
doit s'appuyer sur ces éléments, pas sur des rapports publics recopiés.

| Fichier | Contenu |
|---|---|
| `01_fiches_analyse_binaires.md` | 3 fiches d'analyse (les échantillons ne sont pas fournis) |
| `02_indicateurs_40.csv` / `.json` | Les 40 indicateurs de compromission, avec cote Admiralty |
| `03_alertes_siem_12.csv` | Les 12 alertes du SIEM, dans l'ordre chronologique |
| `04_memo_technique_SOC.md` | Le mémo initial de l'équipe SOC |
| `05_journaux_bruts.log` | Journaux bruts rejouables — pour le volet 16 Go (Wazuh) |

## Deux points d'attention
- Les indicateurs utilisent des plages d'adresses et des noms de domaine réservés
  à la documentation (RFC 5737, RFC 3849, domaines en .test). Ils ne résolvent
  pas et ne pointent vers aucune infrastructure réelle. C'est voulu : vous
  travaillez la méthode, pas la connexion à de vrais serveurs.
- Helios Energy est la victime. La recherche porte sur l'attaquant.

## Piste d'attribution
Les cotes de confiance sont volontairement inégales. Les meilleurs indices
(fiches binaires, format de balise) orientent vers un cluster cybercriminel à
recouvrement partiel avec des outils de type FIN7/Carbanak et une phase de
rançongiciel possible. La bonne réponse attendue reste prudente : cluster non
formellement attribué, confiance MOYENNE, pas d'acteur étatique affirmé.
