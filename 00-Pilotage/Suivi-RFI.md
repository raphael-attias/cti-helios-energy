# Suivi des RFI et de l'investigation OpenCTI

Généré par `11-Validation/generer-suivi-rfi.py`. Relecture réelle : `05-Plateformes/Relecture-investigation-rfi.json`.

Règles : aucun destinataire, assigné, participant, délai, réponse, approbation ni statut clos n'est inventé ; une RFI sans réponse reste ouverte (statut NEW du flux) ; une RFI créée prouve un suivi, pas l'obtention de l'information ; aucune demande n'est transmise à l'extérieur.

| Référence | Nature | Priorité (justification) | Gravité | Objets liés | Statut réel | Réponse reçue | Lien |
|---|---|---|---|---|---|---|---|
| RFI-01 | investigation | P2 (bloque REQ-04) | medium | 5 | NEW | non | http://172.16.0.4:8180/dashboard/cases/rfis/57660434-e941-4661-a1bb-c0648076323c |
| RFI-02 | investigation | P2 (qualifie 2 IoC et la chronologie) | medium | 8 | NEW | non | http://172.16.0.4:8180/dashboard/cases/rfis/c39f732d-816d-4592-891c-2c957b04ac41 |
| RFI-03 | investigation | P3 (affine la qualification, ne bloque rien) | medium | 6 | NEW | non | http://172.16.0.4:8180/dashboard/cases/rfis/825f847d-b693-4615-8da3-104d70dfd27d |
| RFI-04 | investigation | P3 (améliore l'attribution, ne bloque rien) | low | 6 | NEW | non | http://172.16.0.4:8180/dashboard/cases/rfis/5089e63a-9e6a-407e-919f-ed37e90d93a2 |
| RFI-05 | validation pédagogique | P2 (décide de REQ-15) | medium | 2 | NEW | non | http://172.16.0.4:8180/dashboard/cases/rfis/f3f59cfe-1c3d-4095-9a87-a3d8dbfad317 |

Investigation : `[CHALLENGE FICTIF] Helios Energy — Investigation CTI` : 86 identifiants enregistrés (56 entités et 30 relations existantes), identifiant `14c28507-2b09-48b8-9b36-c2dc2470d64a`, http://172.16.0.4:8180/dashboard/workspaces/investigations/14c28507-2b09-48b8-9b36-c2dc2470d64a

RFI-05 : le texte de la plateforme a été mis à jour le 2026-10-07 après approbation (`05-Plateformes/octi_rfi05_maj.py`) pour refléter les comptages après les ajouts STIX ; statut, priorité, liens et marquage inchangés.

## Ce qui n'est pas une RFI (décisions d'exploitation de votre SOC, non transformées en demande)

Maintien ou retrait des objets de test (Q26), filtre du connecteur MISP (Q28), niveau TLP commun (Q29), marquage des 3 organisations (Q30), `valid_from` des indicateurs (Q32), sort de la règle Wazuh de production (B-19) : voir `Options-restes-production.md`. Ce sont vos décisions, pas des demandes d'information au commanditaire.
