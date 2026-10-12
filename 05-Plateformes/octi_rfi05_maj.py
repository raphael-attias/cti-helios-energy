#!/usr/bin/env python3
"""Mise à jour du TEXTE de la RFI-05 (la nôtre, approuvée le 2026-10-07) : description et contenu seulement. Statut, priorité, liens, marquage et réponse inchangés. Modes : plan | apply | verify. Exécuté SUR hiboux."""
import json, subprocess, sys, urllib.request
URL = "http://127.0.0.1:8180/graphql"; ID = "f3f59cfe-1c3d-4095-9a87-a3d8dbfad317"
TOKEN = subprocess.check_output(["docker", "exec", "xtm-opencti-1", "printenv", "APP__ADMIN__TOKEN"]).decode().strip()
def gql(q, v=None):
    r = urllib.request.Request(URL, data=json.dumps({"query": q, "variables": v or {}}).encode(), headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=120) as x: return json.loads(x.read())
    except urllib.error.HTTPError as e: return json.loads(e.read() or b"{}")
DESC = "Arbitrage demandé : que recouvre « au moins 25 objets liés » ? Méthode de l'équipe (non confirmée) : 27 objets de renseignement reliés dans une même composante ; autres définitions : 20, 24, 42, 106. Et la liste des 36 exigences est-elle la bonne ?"
CONTENT = """## Questions précises
1. Que recouvre « au moins 25 objets liés » dans le bundle STIX 2.1 ? Méthode retenue par l'équipe, **choix de vérification non confirmé par le commanditaire** : objets de renseignement (campagne, malware, outil, infrastructure, technique, indicateur) extrémités d'une relation explicite et appartenant à la même composante connexe : **27** (25 en retirant les 2 ajouts dont la seule base est le texte d'une alerte). Autres définitions : 20 (quatre types, avant l'ajout de 7 objets prouvés le 2026-10-07), 24 (avec les actifs victimes, avant l'ajout), 42 (tout objet extrémité d'une relation, observables et données observées compris), 106 (avec les références de conteneurs). Cette méthode est-elle acceptée ?
2. La liste des 36 exigences officielles du dossier (lecture du brief, sujet officiel absent) est-elle correcte ?

## Contexte
Le comptage est reproductible (06-STIX-Graphe/generer-liaison-stix.py). Aucun objet n'a été créé pour atteindre le seuil : les 7 ajouts (3 outils, 4 infrastructures) sont chacun prouvés par une ligne du journal brut ou par le détail d'une alerte ; 13 des 27 objets comptés sont au statut « observé », 7 « déclaré », 6 « hypothèse », 1 « non attribué » (la campagne).

## Preuves disponibles
06-STIX-Graphe/Justification-25-objets-lies.md ; 06-STIX-Graphe/Inventaire-liaison-STIX.csv ; 00-Pilotage/Exigences-origine.md.

## Information manquante
La définition retenue par le commanditaire et la confirmation de la liste.

## Impact sur l'analyse
Détermine si REQ-15 reste « satisfait et contrôlé » (méthode de l'équipe) ; une définition limitée aux objets au statut « observé » (13) ne serait pas atteinte. Fixe aussi le dénominateur de la couverture officielle.

## Priorité : P2
Décide de la réussite ou non d'une exigence officielle.

## Résultat attendu
Un choix de définition et la confirmation de la liste.

Type de demande : question de validation pédagogique, pas une demande d'investigation. Aucun destinataire, délai ni réponse n'est supposé. Texte mis à jour le 2026-10-07 (comptages après ajouts)."""
def state():
    return gql('query($id:String!){ caseRfi(id:$id){ id name description content priority severity status{ template{ name } } objectMarking{ definition } objects{ pageInfo{ globalCount } } } }', {"id": ID})["data"]["caseRfi"]
def plan(): s = state(); print(s["name"][:80], "| statut", s["status"]["template"]["name"], "| priorité", s["priority"], "| liens", s["objects"]["pageInfo"]["globalCount"], "| contenu actuel", len(s["content"] or ""), "caractères")
def apply():
    r = gql('mutation($id:ID!,$i:[EditInput!]!){ stixDomainObjectEdit(id:$id){ fieldPatch(input:$i){ id } } }', {"id": ID, "i": [{"key": "description", "value": [DESC]}, {"key": "content", "value": [CONTENT]}]})
    print("ERREUR " + json.dumps(r.get("errors"))[:300] if r.get("errors") else "mis à jour")
def verify(): s = state(); print("RESULT " + json.dumps({"statut": s["status"]["template"]["name"], "priorite": s["priority"], "liens": s["objects"]["pageInfo"]["globalCount"], "marquage": [m["definition"] for m in s["objectMarking"]], "contenu_a_jour": "27" in (s["content"] or "") and "Ajouts-STIX" not in (s["content"] or ""), "longueur": len(s["content"] or "")}))
if __name__ == "__main__": {"plan": plan, "apply": apply, "verify": verify}[sys.argv[1]]()
