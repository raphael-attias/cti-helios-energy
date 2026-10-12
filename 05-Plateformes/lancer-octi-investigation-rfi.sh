#!/bin/bash
# Lance un script OpenCTI de la mission (par défaut octi_investigation_rfi.py ; ou octi_p1_marquage_orgs.py) en mode plan | apply | verify | complete
# sur hiboux via Pharos et Ansible ciblé. Le script temporaire est supprimé ensuite. plan et verify sont en lecture seule ; apply écrit (après approbation explicite).
# Usage : bash lancer-octi-investigation-rfi.sh <mode> [script.py]
set -eu
MODE="${1:-plan}"; SCRIPT="${2:-octi_investigation_rfi.py}"; D="$(cd "$(dirname "$0")" && pwd)"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
python3 - "$D" "$SCRIPT" "$T/octi_inv_rfi.py" <<'PY'
import sys, json
d, script, out = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(d + "/" + script, encoding="utf-8").read().replace("__IDS__", json.dumps(json.load(open(d + "/IDs-OpenCTI.json"))))
import os
for tag, fn in (("__INIT__", "Investigation-etat-initial.json"), ("__NEW__", "IDs-complements-T13.json")):
    if tag in s: s = s.replace(tag, json.dumps(json.load(open(d + "/" + fn))))
open(out, "w", encoding="utf-8").write(s)
PY
scp -q "$T/octi_inv_rfi.py" rapatt@pharos:/tmp/octi_inv_rfi.py
ssh rapatt@pharos "cd ~/ansible && ansible hiboux -b -m script -a '/tmp/octi_inv_rfi.py $MODE' 2>&1 | python3 -c \"import sys,re; t=sys.stdin.read(); m=re.search(r'\\\"stdout\\\": \\\"(.*?)\\\",\\n',t,re.S); print(t[:2000]) if not m else print(m.group(1).encode().decode('unicode_escape').encode('latin-1','ignore').decode('utf-8','ignore'))\"; rm -f /tmp/octi_inv_rfi.py"
