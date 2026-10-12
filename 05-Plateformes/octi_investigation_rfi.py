#!/usr/bin/env python3
"""Investigation et RFI OpenCTI du challenge (exécuté SUR hiboux via Ansible ciblé). Python standard uniquement.
Modes : plan (lecture seule : résout les cibles, détecte les doublons, imprime les charges exactes), apply (écrit, idempotent par nom),
verify (relit ce qui a été enregistré). Le jeton est lu dans l'environnement du conteneur de la plateforme et n'est jamais affiché.
Les identifiants viennent de IDs-OpenCTI.json (remplacé dans __IDS__ par la commande de lancement). Aucune suppression, aucune modification d'objet existant."""
import json, subprocess, sys, urllib.request

URL = "http://127.0.0.1:8180/graphql"
IDS = json.loads('''__IDS__''')
RED = "89158cb3-75d5-467a-89b3-101efcec8cc4"           # TLP:RED (lu dans la plateforme le 2026-10-06)
LAB = IDS["challenge:helios-fictif"]; TEAM = IDS["equipe"]
INV_NAME = "[CHALLENGE FICTIF] Helios Energy — Investigation CTI"   # nom demandé par l'utilisateur (même libellé que le rapport)

def token():
    return subprocess.check_output(["docker", "exec", "xtm-opencti-1", "printenv", "APP__ADMIN__TOKEN"]).decode().strip()
TOKEN = token()

def gql(q, v=None):
    req = urllib.request.Request(URL, data=json.dumps({"query": q, "variables": v or {}}).encode(),
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r: return json.loads(r.read())
    except urllib.error.HTTPError as e: return json.loads(e.read() or b"{}")

def ex(q, v=None):
    r = gql(q, v)
    if r.get("errors"): raise RuntimeError(json.dumps(r["errors"])[:600])
    return r["data"]

# ---------------------------------------------------------------- Investigation : entités à y placer
def investigation_entities():
    F = '{mode:and,filters:[{key:"objectLabel",values:["%s"]}],filterGroups:[]}' % LAB
    core = ex('{ stixCoreObjects(filters:%s, first:500){ edges{ node{ id entity_type } } } }' % F)["stixCoreObjects"]["edges"]
    ents = {e["node"]["id"]: e["node"]["entity_type"] for e in core if e["node"]["entity_type"] != "Case-Rfi"}   # les RFI (étiquetées ensuite) restent hors de la vue
    aps = ex('{ stixCoreRelationships(relationship_type:["uses"], fromId:["%s"], first:50){ edges{ node{ to{ ... on BasicObject{ id entity_type } } } } } }' % IDS["INC"])
    for e in aps["stixCoreRelationships"]["edges"]:
        t = e["node"]["to"]; ents[t["id"]] = t["entity_type"]
    ents[IDS["victime"]] = "Organization"          # l'organisation victime ; les organisations « dossier » et « équipe » ne sont pas incluses
    return ents

INV_DESC = ("Investigation CTI sur l'intrusion INC-2026-0302 (victime fictive Helios Energy). Exercice pédagogique : toutes les données sont fictives (plages de documentation, domaines .test). "
            "Cluster NON ATTRIBUÉ : aucun acteur n'est placé dans cette vue. Lecture suggérée de la vue : chaîne d'attaque (techniques ATT&CK, incident), infrastructure (adresses, URL, certificats), "
            "actifs victimes (3 systèmes et l'organisation), capacités (fichiers BIN), preuves (données observées, indicateurs expirés), hypothèses et inconnues (3 notes). "
            "Rapport de référence : 3ec91c0f-915b-4e1d-9cd9-c1c12c79f342 (le graphe de connaissance complet se consulte sur le rapport).")
INV_TAGS = ["challenge:helios-fictif", "INC-2026-0302", "CTI", "non-attribue"]

# ---------------------------------------------------------------- RFI : cinq demandes regroupées
A = IDS
RFIS = [
 dict(key="RFI-01", kind="investigation", priority="P2", severity="medium",
  name="[CHALLENGE FICTIF] RFI-01 (investigation) Échantillons des trois binaires, ou confirmation que les fiches sont toute la fourniture",
  description="Les trois échantillons décrits par les fiches BIN-001, BIN-002 et BIN-003 ne sont pas fournis. Les fournir (ou des sorties de bac à sable), ou confirmer que les fiches constituent toute la fourniture pédagogique.",
  links=[A["INC"], A["REPORT"], A["OBS-F-BIN001"], A["OBS-F-BIN002"], A["OBS-F-BIN003"]],
  content="""## Question précise
Pouvez-vous fournir les trois échantillons décrits par les fiches (BIN-001 facture_mars_2026.xlsm, BIN-002 svchost_update.exe, BIN-003 rundll32_helper.dll), ou des rapports de bac à sable, ou confirmer par écrit que les fiches constituent la totalité de la fourniture pédagogique ?

## Contexte
Le LISEZ-MOI du dossier indique que les échantillons ne sont pas fournis. Les neuf empreintes déclarées (SHA-256, SHA-1, MD5 pour chaque binaire) sont retrouvées dans le fichier des 40 IoC. La taille de BIN-002 (421376 octets) correspond à la réponse HTTP vue dans le journal Squid : corroboration interne au lot.

## Preuves disponibles
fourniture/00_LISEZ-MOI.md ; fourniture/01_fiches_analyse_binaires.md ; 02-Artefacts/Inventaire-binaires.csv ; 02-Artefacts/Integrite-et-provenance.md (contrôles 3 et 5).

## Information manquante
Les fichiers eux-mêmes, ou des sorties d'analyse dynamique. À défaut : la confirmation écrite que le périmètre est celui des fiches.

## Impact sur l'analyse
Sans échantillon, les empreintes restent déclarées et ne sont pas recalculées, aucune analyse statique n'est possible (exigence REQ-04 bloquée) et les capacités des outils restent à l'état DÉCLARÉ. Aucun rapprochement avec une famille n'est possible.

## Priorité : P2
Seule exigence officielle bloquée du dossier ; n'empêche pas les autres livrables.

## Résultat attendu
Soit les échantillons, à manipuler uniquement en environnement isolé et sans jamais les exécuter ailleurs ; soit la confirmation que la limite est actée et que REQ-04 reste documentée comme limite imputable au dossier.

Type de demande : investigation (avec une part de validation du périmètre de la fourniture). Aucun destinataire, délai ni réponse n'est supposé."""),
 dict(key="RFI-02", kind="investigation", priority="P2", severity="medium",
  name="[CHALLENGE FICTIF] RFI-02 (investigation) Incohérences de dates, d'horloges et d'identifiants à lever",
  description="Six incohérences du lot fourni empêchent de dater et de qualifier certains faits : mémo antérieur aux faits décrits, compte utilisé avant sa création, correspondance des identifiants des fiches, parent du PowerShell, nature de 198.51.100.55, repli connu avant usage.",
  links=[A["INC"], A["REPORT"], A["comptabilite-07"], A["srv-fichiers-02"], A["dc-01"], A["OBS-ACC"], A["OBS-IP-25"], A["OBS-IP-26"]],
  content="""## Questions précises (regroupées, numérotation du registre d'incohérences)
1. I-02 : le mémo SOC est daté du 2026-03-02T10:30Z mais décrit des faits du 5 mars. A-t-il été mis à jour après la date de son en-tête ?
2. I-03 : le compte svc-backup-temp ouvre une session RDP sur srv-fichiers-02 le 2026-03-04 à 01:47 alors que sa création (événement 4720) date du 2026-03-05 à 14:12. Le compte existait-il avant le 5 mars ? Les horloges de srv-fichiers-02 et dc-01 sont-elles synchronisées, et quel est le fuseau du site ?
3. I-13 : à quels numéros du CSV des IoC correspondent les identifiants des fiches (D-01, D-02, D-04, IP-07, IP-08, IP-09, CERT-01, HASH-STAGE) ?
4. I-18 : le parent winword.exe de l'alerte 1 est-il correct alors que BIN-001 est un classeur .xlsm ?
5. I-04 et I-05 : que représente 198.51.100.55 (alerte 6, IoC 25) et quelle est la source du RDP de l'alerte 7 (interne, ou 203.0.113.44, IoC 26) ?
6. I-11 : pourquoi l'infrastructure de repli (IoC 16 et 22) est-elle vue dès le 3 mars alors que l'alerte 11 situe la bascule le 6 mars ?

## Contexte
Dates d'événements : bornes d'observation du 2 au 7 mars 2026, en UTC. Les contradictions sont traitées comme hypothèses ouvertes (HYP-001 et HYP-002), jamais arbitrées en silence.

## Preuves disponibles
02-Artefacts/Integrite-et-provenance.md (I-01 à I-21) ; 04-Analyse/Chronologie.csv ; 04-Analyse/Analyse-alertes.md ; fourniture/03_alertes_siem_12.csv ; fourniture/05_journaux_bruts.log.

## Information manquante
Réponses du fournisseur du lot sur ces six points, ou journaux d'origine permettant de les trancher.

## Impact sur l'analyse
Chronologie et séquence de mouvement latéral (confiance limitée), rôle réel de 198.51.100.55 et 203.0.113.44 (IoC 25 et 26 maintenus non diffusables comme indicateurs offensifs, to_ids=false), mapping ATT&CK de l'alerte 1.

## Priorité : P2
Conditionne la qualification de deux IoC et la fiabilité de la chronologie ; ne bloque aucun livrable.

## Résultat attendu
Une réponse point par point (ou la mention « inconnu » assumée). Les points non résolus restent des inconnues documentées.

Type de demande : investigation. Aucun destinataire, délai ni réponse n'est supposé."""),
 dict(key="RFI-03", kind="investigation", priority="P3", severity="medium",
  name="[CHALLENGE FICTIF] RFI-03 (investigation) Périmètre des actifs, SIIV concernés et conséquences métier",
  description="Le statut OIV d'Helios est fourni par l'énoncé. Quels systèmes sont des SIIV, quel secteur réglementaire s'applique, et que contiennent les 2 469 135 790 octets sortis ?",
  links=[A["INC"], A["REPORT"], A["comptabilite-07"], A["srv-fichiers-02"], A["dc-01"], A["victime"]],
  content="""## Question précise
Helios Energy est présenté comme opérateur d'importance vitale (statut fourni par l'énoncé, retenu tel quel). Quels systèmes d'information sont qualifiés SIIV, les hôtes comptabilite-07, srv-fichiers-02 et dc-01 en font-ils partie, quel arrêté sectoriel s'applique, et que contiennent les 2 469 135 790 octets sortis (données personnelles, secrets industriels, autres) ?

## Contexte
Les rôles des trois hôtes sont déduits de leur nom et du comportement observé. La note ANSSI traite l'obligation OIV comme conditionnelle à un SIIV touché, qui n'est pas établi. Le délai RGPD ne peut être ni écarté ni constaté tant que le contenu est inconnu.

## Preuves disponibles
08-Rapports/Note-reglementaire-ANSSI.md ; 04-Analyse/Cartographie-SI.md ; 04-Analyse/Matrice-risques-CID.csv ; alerte 10 (volume sortant).

## Information manquante
Liste des SIIV, secteur, nature des données sorties, rôle réel des hôtes.

## Impact sur l'analyse
Criticités de la matrice CID (aujourd'hui conditionnelles), obligation de notification (OIV/SIIV, RGPD), gravité métier du rapport stratégique.

## Priorité : P3
Affine la qualification sans bloquer de livrable ; les notes restent valables sous hypothèses explicites.

## Résultat attendu
Les informations, ou la mention qu'elles sont inconnues. Aucune déclaration réelle n'est préparée ni envoyée.

Type de demande : investigation. Aucun destinataire, délai ni réponse n'est supposé."""),
 dict(key="RFI-04", kind="investigation", priority="P3", severity="low",
  name="[CHALLENGE FICTIF] RFI-04 (investigation) Éléments indépendants pour tester l'attribution",
  description="Aucune source indépendante du lot ne permet de tester l'attribution. Quels éléments (hameçonnage d'origine, configuration complète de la balise, journaux complets, certificat, passive DNS, rapport public cité) peuvent être fournis ?",
  links=[A["INC"], A["REPORT"], A["N-ATTRIB"], A["OBS-X-35"], A["OBS-IP-27"], A["OBS-IP-28"]],
  content="""## Question précise
Existe-t-il des éléments indépendants du lot permettant de tester une attribution : courriel d'hameçonnage d'origine, configuration complète de la balise (une seule ligne est fournie), journaux complets (Sysmon 1, 8, 10 ; Security 4624, 4720, 4726, 4698 ; Zeek conn, ssl, notice ; Squid avec user-agent), supports des pivots d'infrastructure (certificat commun, passive DNS partagé), rapport public et campagne de janvier 2026 cités par les IoC 28 et 35 ?

## Contexte
Conclusion actuelle : cluster non attribué, aucun acteur nommé. Le LISEZ-MOI contient une piste d'attribution traitée comme avis de cadrage et non comme preuve. Cotes Admiralty plafonnées faute de sources indépendantes.

## Preuves disponibles
04-Analyse/Hypotheses-et-attribution.md ; 08-Rapports/Note-attribution.md ; 04-Analyse/Diamond-Model.md (pivots non utilisables) ; 02-Artefacts/Integrite-et-provenance.md (I-15, I-16).

## Information manquante
Les supports des pivots et les journaux complets listés ci-dessus.

## Impact sur l'analyse
Sans eux, aucune attribution à un acteur nommé ne peut être testée ; la conclusion prudente reste valide. Avec eux, des hypothèses pourraient être confrontées sur preuves, pas sur la piste du LISEZ-MOI.

## Priorité : P3
Améliore la solidité de l'attribution, ne bloque aucun livrable.

## Résultat attendu
Les éléments, ou la confirmation qu'il n'en existe pas. Aucune recherche externe sur les valeurs d'IoC n'est lancée dans l'attente.

Type de demande : investigation. Aucun destinataire, délai ni réponse n'est supposé."""),
 dict(key="RFI-05", kind="validation-pedagogique", priority="P2", severity="medium",
  name="[CHALLENGE FICTIF] RFI-05 (validation pédagogique) Définition de « objets liés » du bundle STIX et liste des exigences",
  description="Arbitrage demandé : que recouvre « au moins 25 objets liés » (20, 24, 34 ou 99 selon la définition) et la liste des 36 exigences officielles est-elle la bonne ?",
  links=[A["REPORT"], A["N-LIMITES"]],
  content="""## Questions précises
1. Que recouvre « au moins 25 objets liés » dans le bundle STIX 2.1 : (a) objets analytiques seuls, 20 aujourd'hui ; (b) objets analytiques et identités, 24 ; (c) tout objet extrémité d'une relation, 34 ; (d) tout objet référencé par une relation ou un conteneur, 99 ?
2. La liste des 36 exigences officielles du dossier (lecture du brief, sujet officiel absent) est-elle correcte ?

## Contexte
Le comptage est reproductible (06-STIX-Graphe/generer-liaison-stix.py). Sous la définition conservatrice (a), l'exigence n'est pas démontrée. Aucun objet n'est créé pour atteindre le seuil.

## Preuves disponibles
06-STIX-Graphe/Justification-25-objets-lies.md ; 06-STIX-Graphe/Inventaire-liaison-STIX.csv ; 06-STIX-Graphe/Ajouts-STIX-proposes.md ; 00-Pilotage/Exigences-origine.md.

## Information manquante
La définition retenue par le commanditaire et la confirmation de la liste.

## Impact sur l'analyse
Détermine le statut de REQ-15 (aujourd'hui À CONTRÔLER) et le dénominateur de la couverture officielle.

## Priorité : P2
Décide de la réussite ou non d'une exigence officielle.

## Résultat attendu
Un choix de définition (et, le cas échéant, l'approbation des ajouts d'objets justifiés listés dans Ajouts-STIX-proposes.md).

Type de demande : question de validation pédagogique, pas une demande d'investigation. Aucun destinataire, délai ni réponse n'est supposé."""),
]

def existing():
    inv = ex('{ workspaces(first:100){ edges{ node{ id name type } } } }')["workspaces"]["edges"]
    rf = ex('{ caseRfis(first:100){ edges{ node{ id name } } } }')["caseRfis"]["edges"]
    return [e["node"] for e in inv], [e["node"] for e in rf]

def plan():
    ents = investigation_entities(); invs, rfis = existing()
    import collections
    print("## ÉTAT ACTUEL")
    print("enquêtes existantes :", [(w["name"], w["id"]) for w in invs if w["type"] == "investigation"])
    print("RFI existantes :", [(r["name"], r["id"]) for r in rfis])
    print("doublon enquête :", any(w["name"] == INV_NAME for w in invs), "| doublons RFI :", [r["key"] for r in RFIS if any(x["name"] == r["name"] for x in rfis)])
    print("## CHARGE ENQUÊTE")
    print(json.dumps({"type": "investigation", "name": INV_NAME, "description": INV_DESC, "tags": INV_TAGS, "investigated_entities_ids": len(ents)}, ensure_ascii=False, indent=1))
    print("entités par type :", dict(collections.Counter(ents.values())))
    print("## CHARGES RFI")
    for r in RFIS:
        print(json.dumps({"key": r["key"], "kind": r["kind"], "name": r["name"], "priority": r["priority"], "severity": r["severity"], "status": "NEW (défaut du flux)",
                          "createdBy": "équipe CTI fictive", "objectMarking": "TLP:RED", "objectLabel": "challenge:helios-fictif", "assignee": None, "participants": None,
                          "objets_liés": len(r["links"]), "longueur_contenu": len(r["content"])}, ensure_ascii=False))

def inv_relations(ents):
    """Relations (core et sightings) EXISTANTES dont les deux extrémités sont dans l'enquête. Aucune création."""
    F = '{mode:and,filters:[{key:"objectLabel",values:["%s"]}],filterGroups:[]}' % LAB
    found = {}
    for e in ex('{ stixCoreRelationships(filters:%s, first:500){ edges{ node{ id relationship_type from{ ... on BasicObject{ id } } to{ ... on BasicObject{ id } } } } } }' % F)["stixCoreRelationships"]["edges"]:
        n = e["node"]; found[n["id"]] = (n["relationship_type"], n["from"]["id"] if n["from"] else None, n["to"]["id"] if n["to"] else None)
    for e in ex('{ stixCoreRelationships(fromId:["%s"], first:100){ edges{ node{ id relationship_type from{ ... on BasicObject{ id } } to{ ... on BasicObject{ id } } } } } }' % IDS["INC"])["stixCoreRelationships"]["edges"]:
        n = e["node"]; found[n["id"]] = (n["relationship_type"], n["from"]["id"] if n["from"] else None, n["to"]["id"] if n["to"] else None)
    for k in IDS:
        if k.startswith("IND-"):
            for e in ex('query($f:[String]){ stixCoreRelationships(fromId:$f, first:50){ edges{ node{ id relationship_type from{ ... on BasicObject{ id } } to{ ... on BasicObject{ id } } } } } }', {"f": [IDS[k]]})["stixCoreRelationships"]["edges"]:
                n = e["node"]; found[n["id"]] = (n["relationship_type"], n["from"]["id"] if n["from"] else None, n["to"]["id"] if n["to"] else None)
            for e in ex('query($f:StixRef){ stixSightingRelationships(fromId:$f, first:50){ edges{ node{ id from{ ... on BasicObject{ id } } to{ ... on BasicObject{ id } } } } } }', {"f": IDS[k]})["stixSightingRelationships"]["edges"]:
                n = e["node"]; found[n["id"]] = ("sighting", n["from"]["id"] if n["from"] else None, n["to"]["id"] if n["to"] else None)
    keep = {i: v for i, v in found.items() if v[1] in ents and v[2] in ents}
    return keep, found

def complete():
    """Ajoute à l'enquête de la mission les relations existantes entre ses entités (workspaceFieldPatch sur NOTRE enquête uniquement)."""
    invs, _ = existing(); w = next(x for x in invs if x["name"] == INV_NAME)
    ents = investigation_entities(); keep, found = inv_relations(ents)
    import collections
    print("relations candidates :", len(found), "| dont extrémités toutes dans l'enquête :", len(keep), dict(collections.Counter(v[0] for v in keep.values())))
    ids_all = sorted(set(ents) | set(keep))
    ex('mutation($id:ID!,$i:[EditInput!]!){ workspaceFieldPatch(id:$id, input:$i){ id } }', {"id": w["id"], "i": [{"key": "investigated_entities_ids", "value": ids_all}]})
    d = ex('query($id:String!){ workspace(id:$id){ investigated_entities_ids } }', {"id": w["id"]})["workspace"]["investigated_entities_ids"] or []
    print("enregistré :", len(d), "identifiants (entités + relations)")

def apply():
    ents = investigation_entities(); invs, rfis = existing(); out = {}
    if any(w["name"] == INV_NAME for w in invs):
        out["investigation"] = next(w["id"] for w in invs if w["name"] == INV_NAME); print("enquête déjà présente", out["investigation"])
    else:
        d = ex('mutation($i:WorkspaceAddInput!){ workspaceAdd(input:$i){ id name type } }',
               {"i": {"type": "investigation", "name": INV_NAME, "description": INV_DESC, "tags": INV_TAGS, "investigated_entities_ids": sorted(ents)}})
        out["investigation"] = d["workspaceAdd"]["id"]; print("enquête créée", out["investigation"])
    for r in RFIS:
        m = next((x for x in rfis if x["name"] == r["name"]), None)
        if m: out[r["key"]] = m["id"]; print(r["key"], "déjà présente", m["id"]); continue
        i = {"name": r["name"], "description": r["description"], "content": r["content"], "severity": r["severity"], "priority": r["priority"], "createdBy": TEAM,
             "objectMarking": [RED], "objectLabel": [LAB], "objects": sorted(set(r["links"]))}
        d = ex('mutation($i:CaseRfiAddInput!){ caseRfiAdd(input:$i){ id name } }', {"i": i}); out[r["key"]] = d["caseRfiAdd"]["id"]; print(r["key"], "créée", out[r["key"]])
    print("RESULT " + json.dumps(out))

def verify():
    invs, rfis = existing(); out = {}
    for w in invs:
        if w["name"] == INV_NAME:
            d = ex('query($id:String!){ workspace(id:$id){ id name type tags description investigated_entities_ids currentUserAccessRight authorizedMembers{ name access_right } objects{ pageInfo{ globalCount } } created_at } }', {"id": w["id"]})["workspace"]
            ids_ = d.pop("investigated_entities_ids") or []; d["investigated_entities"] = len(ids_); d["description"] = d["description"][:80] + "..."; out["investigation"] = d
    for r in RFIS:
        m = next((x for x in rfis if x["name"] == r["name"]), None)
        if m:
            d = ex('query($id:String!){ caseRfi(id:$id){ id name priority severity created_at status{ template{ name } } createdBy{ name } objectMarking{ definition } objectLabel{ value } objectAssignee{ name } objectParticipant{ name } objects{ pageInfo{ globalCount } } content } }', {"id": m["id"]})["caseRfi"]
            d["content_len"] = len(d.pop("content") or ""); out[r["key"]] = d
    print("RESULT " + json.dumps(out, ensure_ascii=False))

if __name__ == "__main__":
    {"plan": plan, "apply": apply, "verify": verify, "complete": complete}[sys.argv[1] if len(sys.argv) > 1 else "plan"]()
