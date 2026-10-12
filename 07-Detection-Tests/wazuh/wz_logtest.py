#!/var/ossec/framework/python/bin/python3
"""Rejoue les événements du TSV dans wazuh-logtest (socket) DANS le conteneur de test isolé. Sortie JSON : id, règle obtenue, décodeur, champs."""
import json, socket, struct, sys
def q(msg):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("/var/ossec/queue/sockets/logtest")
    b = json.dumps(msg).encode(); s.send(struct.pack("<I", len(b)) + b)
    n = struct.unpack("<I", s.recv(4))[0]; d = b""
    while len(d) < n: d += s.recv(n - len(d))
    s.close(); return json.loads(d)
token = None; out = []
for line in open(sys.argv[1], encoding="utf-8"):
    eid, orig, exp, ev = line.rstrip("\n").split("\t", 3)
    p = {"event": ev, "log_format": "syslog", "location": "helios-test"}
    if token: p["token"] = token
    r = q({"version": 1, "command": "log_processing", "parameters": p})
    d = r.get("data", {}); token = d.get("token", token)
    o = d.get("output", {})
    out.append({"id": eid, "origine": orig, "attendu": exp, "regle": (o.get("rule") or {}).get("id", ""), "niveau": (o.get("rule") or {}).get("level", ""), "alerte": d.get("alert", False),
                "decodeur": (o.get("decoder") or {}).get("name", ""), "champs": o.get("data", {}), "predecodeur": o.get("predecoder", {}), "erreur": r.get("error", 0), "messages": d.get("messages", [])[:2]})
json.dump(out, open(sys.argv[2], "w"), ensure_ascii=False, indent=1)
print(len(out), "événements traités")
