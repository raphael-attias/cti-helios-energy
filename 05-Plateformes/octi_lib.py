#!/usr/bin/env python3
"""Outils OpenCTI du challenge, exécutés SUR hiboux via Ansible (ciblé). Le jeton est lu dans l'environnement du conteneur
de la plateforme (xtm-opencti-1) à l'exécution et n'est jamais affiché ni écrit. Python standard uniquement."""
import json, subprocess, sys, urllib.request

URL = "http://127.0.0.1:8180/graphql"

def _token():
    return subprocess.check_output(["docker", "exec", "xtm-opencti-1", "printenv", "APP__ADMIN__TOKEN"]).decode().strip()

TOKEN = _token()

def gql(query, variables=None):
    req = urllib.request.Request(URL, data=json.dumps({"query": query, "variables": variables or {}}).encode(),
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")

def read2():
    d = gql("{ markingDefinitions(first:100){ edges { node { id definition definition_type } } } }")
    print("TLP/PAP :", [(e["node"]["definition"], e["node"]["id"]) for e in d["data"]["markingDefinitions"]["edges"] if e["node"]["definition_type"] in ("TLP", "PAP")])
    d = gql('{ labels(first:200){ edges { node { id value } } } }')
    print("LABEL du filtre Jira :", [e["node"]["value"] for e in d["data"]["labels"]["edges"] if e["node"]["id"] == "5b16820b-bf05-441c-8ecf-0a2c8f0fc8fe"])
    print("labels challenge existants :", [e["node"]["value"] for e in d["data"]["labels"]["edges"] if "challenge" in e["node"]["value"].lower()])
    r = gql("{ schemaRelationsTypesMapping { key values { name } } }"); print("schemaRelationsTypesMapping :", str(r)[:400])
    r = gql('{ stixCoreRelationshipsNumber { total } }'); print("nb relations :", r.get("data"))
    for t in ("Incident", "Report", "Note", "Indicator", "StixFile", "IPv4-Addr", "Url", "X509-Certificate", "User-Account", "Directory", "Observed-Data", "System", "Organization", "Label"):
        r = gql('{ __type(name:"%s"){ name } }' % t.replace("-", "")); 
    r = gql('{ __type(name:"StixCoreRelationshipAddInput"){ inputFields { name } } }'); print("RelationAdd champs :", [f["name"] for f in r["data"]["__type"]["inputFields"]][:25])
    r = gql('{ __type(name:"StixSightingRelationshipAddInput"){ inputFields { name } } }'); print("SightingAdd champs :", [f["name"] for f in r["data"]["__type"]["inputFields"]][:30])
    r = gql('{ __type(name:"IncidentAddInput"){ inputFields { name } } }'); print("IncidentAdd champs :", [f["name"] for f in r["data"]["__type"]["inputFields"]])
    r = gql('{ __type(name:"ObservedDataAddInput"){ inputFields { name } } }'); print("ObservedDataAdd champs :", [f["name"] for f in r["data"]["__type"]["inputFields"]])
    r = gql('{ __type(name:"IndicatorAddInput"){ inputFields { name } } }'); print("IndicatorAdd champs :", [f["name"] for f in r["data"]["__type"]["inputFields"]])
    r = gql('{ __type(name:"ReportAddInput"){ inputFields { name } } }'); print("ReportAdd champs :", [f["name"] for f in r["data"]["__type"]["inputFields"]])

def read1():
    print("version :", gql("{ about { version } }")["data"]["about"]["version"])
    d = gql("{ streamCollections(first:20){ edges { node { id name description stream_public stream_live filters } } } }")
    for e in d["data"]["streamCollections"]["edges"]:
        n = e["node"]; print("STREAM", n["id"], n["name"], "public=", n["stream_public"], "live=", n["stream_live"]); print("  filters =", n["filters"])
    d = gql("{ markingDefinitions(first:50){ edges { node { id definition definition_type x_opencti_order } } } }")
    print("MARKINGS :", [(e["node"]["definition"], e["node"]["id"]) for e in d["data"]["markingDefinitions"]["edges"]])
    for tid in ("T1059.001", "T1564.003", "T1105", "T1053.005", "T1046", "T1021.001", "T1055", "T1070.001", "T1055.012"):
        q = '{ attackPatterns(filters:{mode:and,filters:[{key:"x_mitre_id",values:["%s"]}],filterGroups:[]}, first:3){ edges { node { id name x_mitre_id } } } }' % tid
        r = gql(q); es = r.get("data", {}).get("attackPatterns", {}).get("edges", []) if r.get("data") else []
        print("AP", tid, [(e["node"]["name"], e["node"]["id"]) for e in es] or r.get("errors", "?"))
    r = gql("{ schemaRelationsTypesMapping { key values { name } } }")
    m = {x["key"]: [v["name"] for v in x["values"]] for x in r["data"]["schemaRelationsTypesMapping"]}
    for k in ("Incident_Attack-Pattern", "Incident_Identity", "Incident_System", "Incident_Organization", "Indicator_Incident", "Domain-Name_IPv4-Addr", "Indicator_IPv4-Addr", "Indicator_StixFile", "Indicator_Url", "Indicator_Domain-Name"):
        print("REL", k, m.get(k))
    print("REL clés disponibles pour Incident :", [k for k in m if k.startswith("Incident_")][:12])

if __name__ == "__main__":
    globals()[sys.argv[1]]()
