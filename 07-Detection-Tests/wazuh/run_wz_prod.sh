#!/bin/bash
# Déploiement CIBLÉ sur le manager Wazuh de production (docker, VM 127). Deux fichiers NOUVEAUX, aucun fichier existant modifié.
set -u
D=/tmp/wz-challenge; C=single-node-wazuh.manager-1
case "$1" in
 deploy)
  docker exec $C ls /var/ossec/etc/rules /var/ossec/etc/decoders | tr '\n' ' ' > $D/prod-initial-listing.txt
  docker cp $D/helios_decoders.xml $C:/var/ossec/etc/decoders/helios_decoders.xml
  docker cp $D/helios_rules_prod.xml $C:/var/ossec/etc/rules/helios_rules.xml
  docker exec $C chown wazuh:wazuh /var/ossec/etc/decoders/helios_decoders.xml /var/ossec/etc/rules/helios_rules.xml
  docker exec $C chmod 660 /var/ossec/etc/decoders/helios_decoders.xml /var/ossec/etc/rules/helios_rules.xml
  echo "--- validation (wazuh-analysisd -t) en production"; docker exec $C /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5; RC=${PIPESTATUS[0]}; echo "rc=$RC"
  if [ "$RC" != "0" ]; then echo "ECHEC : retrait des deux fichiers"; docker exec $C rm -f /var/ossec/etc/decoders/helios_decoders.xml /var/ossec/etc/rules/helios_rules.xml; exit 1; fi
  echo "validation OK";;
 restart)
  docker exec $C /var/ossec/bin/wazuh-control restart 2>&1 | tail -4
  for i in $(seq 1 30); do sleep 5; docker exec $C /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-apid is running" && break; done
  docker exec $C /var/ossec/bin/wazuh-control status 2>&1 | grep -E "analysisd|remoted|apid|db|modulesd|logcollector";;
 logtest)
  docker cp $D/events-wazuh.tsv $C:/tmp/events.tsv; docker cp $D/wz_logtest.py $C:/tmp/wz_logtest.py
  docker exec $C /var/ossec/framework/python/bin/python3 /tmp/wz_logtest.py /tmp/events.tsv /tmp/out.json && docker cp $C:/tmp/out.json $D/logtest-prod-out.json
  docker exec $C rm -f /tmp/events.tsv /tmp/wz_logtest.py /tmp/out.json;;
 replay)
  docker cp $D/events-wazuh.tsv $C:/tmp/events.tsv; docker cp $D/wz_api_replay.py $C:/tmp/wz_api_replay.py
  docker exec $C /var/ossec/framework/python/bin/python3 /tmp/wz_api_replay.py /tmp/events.tsv "$2" "$3"
  docker exec $C rm -f /tmp/events.tsv /tmp/wz_api_replay.py;;
 count)
  docker exec $C sh -c 'grep helios_challenge /var/ossec/logs/alerts/alerts.json | wc -l; grep helios_challenge /var/ossec/logs/alerts/alerts.json | grep -o "\"id\":\"1301[0-9][0-9]\"" | sort | uniq -c' ;;
 export)
  docker exec $C sh -c 'grep helios_challenge /var/ossec/logs/alerts/alerts.json' > $D/prod-alerts-helios.json; wc -l $D/prod-alerts-helios.json;;
 indexer)
  docker exec $C sh -c 'curl -sk -u "$INDEXER_USERNAME:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_count" -H "Content-Type: application/json" -d "{\"query\":{\"match\":{\"rule.groups\":\"helios_challenge\"}}}"'; echo
  docker exec $C sh -c 'curl -sk -u "$INDEXER_USERNAME:$INDEXER_PASSWORD" "$INDEXER_URL/wazuh-alerts-*/_search?size=0" -H "Content-Type: application/json" -d "{\"query\":{\"match\":{\"rule.groups\":\"helios_challenge\"}},\"aggs\":{\"r\":{\"terms\":{\"field\":\"rule.id\",\"size\":30}},\"idx\":{\"terms\":{\"field\":\"_index\"}}}}"' | python3 -c "import sys,json; d=json.load(sys.stdin); print({b['key']:b['doc_count'] for b in d['aggregations']['r']['buckets']}); print([ (b['key'],b['doc_count']) for b in d['aggregations']['idx']['buckets']])";;
 thehive)
  docker exec $C sh -c 'tail -5 /var/ossec/logs/integrations.log 2>/dev/null | cut -c1-200; ls -la /var/ossec/logs/integrations.log 2>&1 | cut -c1-120';;
 rollback)
  docker exec $C rm -f /var/ossec/etc/decoders/helios_decoders.xml /var/ossec/etc/rules/helios_rules.xml; docker exec $C /var/ossec/bin/wazuh-control restart 2>&1 | tail -2; echo "retour arrière effectué";;
esac
