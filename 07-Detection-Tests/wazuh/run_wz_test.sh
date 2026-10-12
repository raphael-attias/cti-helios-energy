#!/bin/bash
# Exécuté sur l'hôte Wazuh (VM 127) via Ansible. Crée un conteneur de test ISOLE (sans réseau, sans volume de production).
set -u
D=/tmp/wz-challenge; N=wazuh-challenge-test
case "$1" in
 start)
  docker rm -f $N >/dev/null 2>&1
  docker run -d --name $N --network none --memory 2g --cpus 2 --label challenge=helios-fictif wazuh/wazuh-manager:4.14.7 >/dev/null && echo "conteneur $N démarré (réseau none)"
  for i in $(seq 1 40); do sleep 5; docker exec $N /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running" && { echo "analysisd en marche après $((i*5)) s"; break; }; done
  docker exec $N /var/ossec/bin/wazuh-control status 2>&1 | head -20;;
 load)
  docker cp $D/helios_decoders.xml $N:/var/ossec/etc/decoders/helios_decoders.xml && docker cp $D/helios_rules.xml $N:/var/ossec/etc/rules/helios_rules.xml
  docker exec $N chown wazuh:wazuh /var/ossec/etc/decoders/helios_decoders.xml /var/ossec/etc/rules/helios_rules.xml
  echo "--- vérification de configuration (wazuh-analysisd -t)"; docker exec $N /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -8; echo "rc=$?"
  docker exec $N /var/ossec/bin/wazuh-control restart 2>&1 | tail -3; sleep 20
  docker exec $N /var/ossec/bin/wazuh-control status 2>&1 | grep analysisd;;
 logtest)
  docker cp $D/events-wazuh.tsv $N:/tmp/events.tsv; docker cp $D/wz_logtest.py $N:/tmp/wz_logtest.py
  docker exec $N /var/ossec/framework/python/bin/python3 /tmp/wz_logtest.py /tmp/events.tsv /tmp/out.json && docker cp $N:/tmp/out.json $D/logtest-out.json;;
 e2e)
  docker cp $D/events-e2e.log $N:/var/log/helios-replay.log
  docker exec $N sh -c 'grep -q helios-replay /var/ossec/etc/ossec.conf || sed -i "s#</ossec_config>#  <localfile><log_format>syslog</log_format><location>/var/log/helios-replay.log</location></localfile>\n</ossec_config>#" /var/ossec/etc/ossec.conf'
  docker exec $N /var/ossec/bin/wazuh-control restart 2>&1 | tail -2; sleep 40
  docker exec $N sh -c 'ls -la /var/ossec/logs/alerts/; wc -l /var/ossec/logs/alerts/alerts.json; grep -c "\"helios_challenge\"" /var/ossec/logs/alerts/alerts.json'
  docker exec $N cat /var/ossec/logs/alerts/alerts.json > $D/e2e-alerts.json 2>/dev/null; echo "alerts.json copié";;
 info) docker exec $N sh -c 'ls /var/ossec/etc | head -30; /var/ossec/bin/wazuh-control info | head -3';;
 stop) docker rm -f $N >/dev/null 2>&1; rm -rf $D; echo "conteneur $N et $D supprimés (test uniquement)";;
esac
