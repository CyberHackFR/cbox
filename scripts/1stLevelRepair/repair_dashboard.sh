#!/bin/bash
set -e
# Log file to use
# Create path if allowed or do NOP
mkdir -p /var/log/cbox/1stLevelRepair || :
LOG_DIR="/var/log/cbox/1stLevelRepair"
if [[ ! -w $LOG_DIR ]]; then
  LOG_DIR="$HOME"
fi

LOG=$LOG_DIR/insert_dashboards.log

# Do not use interactive debian frontend.
export DEBIAN_FRONTEND=noninteractive

# Forward fd2 to the console
# exec 2>&1
# Forward fd1 to $LOG
exec 2>&1 1>>${LOG}

echo -n "Inserting Dashboards.. " 1>&2
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/Accueil/Accueil.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/SIEM/SIEM-Alarme.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/SIEM/SIEM-ASN.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/SIEM/SIEM-DNS.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/SIEM/SIEM-HTTP.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/SIEM/SIEM-ProtocolesEtServices.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/SIEM/SIEM-SocialMedia.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/SIEM/SIEM-Apercu.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/Reseau/Presentation-Reseau.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/Reseau/Reseau-GeoIPetASN.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/Reseau/Flux-Donnees.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/Vulnerabilite/Details-Vulnerabilite.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/Vulnerabilite/Historique-Vulnerabilites.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/Vulnerabilite/Apercu-Vulnerabilite.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/System/docker.ndjson
echo "[ DONE ]" 1>&2

echo -n "Inserting Patterns.. " 1>&2
# Installiere Suricata Index Pattern
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/Patterns/suricata.ndjson

# Installiere Scores Index Pattern
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$CBOX_INSTALL_DIR/config/dashboards/Patterns/scores.ndjson

# Erstelle initialen VulnWhisperer Index
curl -s -XPUT "localhost:9200/logstash-vulnwhisperer-$(date +%Y.%m)"
echo "[ DONE ]" 1>&2
