#!/bin/bash
#
# Placeholder for TAG=
# The Tag will be the highest version, so the goal of the update
function testNet() {
  # Returns 0 for successful internet connection and dns resolution, 1 else
  ping -q -c 1 -W 1 $1 >/dev/null;
  return $?
}

function waitForNet() {
  # use argument or default value of google.com
  HOST=${1:-"google.com"}
  while ! testNet $HOST; do
    # while testNet returns non zero value
    echo "No internet connectivity or dns resolution of $HOST, sleeping for 15s"
    sleep 15s
  done
}
function rollback() {
  echo "Démarrer la restauration sur $1"
  echo "Réinstaller les packages désinstallés"
  # reinstall uninstalled packages today.
  apt install -y $(grep Remove /var/log/apt/history.log -B3 | grep $(date "+%Y-%m-%d") -A3 | grep "Remove: " | sed -e 's|Remove: ||g' -e 's|([^)]*)||g' -e 's|:[^ ]* ||g' -e 's|,||g')

  echo "Restore database backup"
  docker cp /var/lib/cbox/backup/cbox_db_$1.tar db:/root/cbox_db.tar
  docker exec db /bin/bash -c "PGPASSWORD=$POSTGRES_PASSWORD PGUSER=$POSTGRES_USER pg_restore -F t --clean -d cbox_db /root/cbox_db.tar"

  echo "Restaurer la configuration client"
  tar -C /var/lib/cbox/backup/ -vxf /var/lib/cbox/backup/etc_cbox_$1.tar
  # Restore /etc/cbox to state of cbox/ folder we got from unpacking the tar ball
  cd /var/lib/cbox/backup
  rsync -Iavz --delete cbox/ /etc/cbox
  rm -r cbox/
  cp /var/lib/cbox/backup/resolv.personal /var/lib/cbox/resolv.personal
  rm -f /var/lib/cbox/backup/resolv.personal
  cp /var/lib/cbox/backup/15_logstash_suppress.conf /var/lib/cbox/15_logstash_suppress.conf
  cp /var/lib/cbox/backup/suricata_suppress.bpf /var/lib/cbox/suricata_suppress.bpf
  cp /var/lib/cbox/backup/alert_mail.conf /var/lib/cbox/alert_mail.conf || : # dont fail if this file didn't exist
  rm -f /var/lib/cbox/backup/15_logstash_suppress.conf
  rm -f /var/lib/cbox/backup/suricata_suppress.bpf
  rm -f /var/lib/cbox/backup/alert_mail.conf
  cp /var/lib/cbox/backup/suricata.env $CBOX_CONFIG_DIR/.env.suri
  rm -f /var/lib/cbox/backup/suricata.env

  echo "Restaurer la configuration du système"
  cp /var/lib/cbox/backup/hosts /etc/hosts
  rm -f /var/lib/cbox/backup/hosts
  cp /var/lib/cbox/backup/environment /etc/environment
  rm -f /var/lib/cbox/backup/environment
  cp /var/lib/cbox/backup/msmtprc /etc/msmtprc
  rm -f /var/lib/cbox/backup/msmtprc
  cp /var/lib/cbox/backup/sudoers /etc/sudoers
  rm -f /var/lib/cbox/backup/sudoers
  cp /var/lib/cbox/backup/interfaces /etc/network/interfaces
  rm -f /var/lib/cbox/backup/interfaces
  cp -R /var/lib/cbox/backup/ssl/* /etc/nginx/certs/
  rm -rf /var/lib/cbox/backup/ssl

  echo "Restaurer la documentation"
  rm -rf /var/lib/cbox_docs/*
  cp -R /var/lib/cbox/backup/wiki/* /var/lib/cbox_docs/
  rm -rf /var/lib/cbox/backup/wiki

  echo "Restaurer les alarmes configurées"
  rm -rf /var/lib/elastalert/rules/*
  cp -R /var/lib/cbox/backup/alerts/* /var/lib/elastalert/rules/
  rm -rf /var/lib/cbox/backup/alerts

  cd $CBOX_INSTALL_DIR
  git fetch
  git checkout -f $1 >/dev/null 2>&1

  # Rolling back jvm settings
  cp /var/lib/cbox/backup/.env.es $CBOX_CONFIG_DIR/.env.es
  cp /var/lib/cbox/backup/.env.ls $CBOX_CONFIG_DIR/.env.ls
  rm -f /var/lib/cbox/backup/.env.es /var/lib/cbox/backup/.env.ls

  echo "Rétablir le service à la version $1"
  cp $CBOX_INSTALL_DIR/config/etc/systemd/cbox.service /etc/systemd/system/cbox.service

  # sleep to wait for established connection
  sleep 8

  echo "Réinitialiser le service à la version $1"
  docker-compose -f $CBOX_INSTALL_DIR/docker/cbox.yml pull -q
  docker-compose -f $CBOX_INSTALL_DIR/docker/wazuh/wazuh.yml pull -q

  echo "Redémarrez le CBox."
  # set version in file
  echo "VERSION=$1" > /var/lib/cbox/VERSION
  echo "CBOX_ENV=$ENV" >> /var/lib/cbox/VERSION
  # restart box, causes start of the images of Version $1
  systemctl restart cbox

  # Supprimer la mauvaise balise localement
  cd $CBOX_INSTALL_DIR
  git tag -d $2

  $CBOX_INSTALL_DIR/scripts/System_Scripts/wait-for-healthy-container.sh web
  # Notify API that we're finished rolling back
  echo "rollback-successful" > /var/lib/cbox/.update.state
  echo "Récupération terminée à 1$."

  # Prepare new update.sh for next update
  chown cboxadmin:cboxadmin $CBOX_INSTALL_DIR/scripts/Automation/update.sh
  chmod +x $CBOX_INSTALL_DIR/scripts/Automation/update.sh
  curl -sLk -XDELETE https://localhost/api/update/status/ > /dev/null
  sleep 5
  # Exit update with error code
  exit 1
}
function backup() {
  mkdir -p /var/lib/cbox/backup/

  echo "Créez une sauvegarde à partir de l'état actuel: $1"
  echo "Créer une sauvegarde de base de données"
  docker exec db /bin/bash -c "PGPASSWORD=$POSTGRES_PASSWORD PGUSER=$POSTGRES_USER pg_dump -F tar cbox_db > /root/cbox_db.tar"
  docker cp db:/root/cbox_db.tar /var/lib/cbox/backup/cbox_db_$PRIOR.tar

  echo "Créer une sauvegarde de la configuration client"
  # Backing up /etc/cbox
  tar -C /etc -cvpf /var/lib/cbox/backup/etc_cbox_$PRIOR.tar cbox/
  cp /var/lib/cbox/resolv.personal /var/lib/cbox/backup/resolv.personal
  cp /var/lib/cbox/15_logstash_suppress.conf /var/lib/cbox/backup/15_logstash_suppress.conf
  cp /var/lib/cbox/suricata_suppress.bpf /var/lib/cbox/backup/suricata_suppress.bpf
  cp /var/lib/cbox/alert_mail.conf /var/lib/cbox/backup/alert_mail.conf || : # dont fail if this file doesnt exist (yet)
  cp $CBOX_CONFIG_DIR/.env.suri /var/lib/cbox/backup/suricata.env

  echo "Créer une sauvegarde de la configuration du système"
  cp /etc/hosts /var/lib/cbox/backup/hosts
  cp /etc/environment /var/lib/cbox/backup/environment
  cp /etc/msmtprc /var/lib/cbox/backup/msmtprc
  cp /etc/sudoers /var/lib/cbox/backup/sudoers
  cp /etc/network/interfaces /var/lib/cbox/backup/
  mkdir -p /var/lib/cbox/backup/ssl
  cp -R /etc/nginx/certs/* /var/lib/cbox/backup/ssl/

  echo "Créer une sauvegarde de la documentation"
  mkdir -p /var/lib/cbox/backup/wiki
  cp -R /var/lib/cbox_docs/* /var/lib/cbox/backup/wiki/

  echo "Créer une sauvegarde des alarmes configurées"
  mkdir -p /var/lib/cbox/backup/alerts
  cp -R /var/lib/elastalert/rules/* /var/lib/cbox/backup/alerts
}

#The sleep instructions are for demo only and can be removed
exec 1>/var/log/cbox/update.log && exec 2>&1
# Notify API that we're starting
# Follow redirects, accept invalid certificate and dont produce output
curl -sLk -XPOST https://localhost/api/update/status/ -H "Content-Type: application/json" -d '{"status":"running"}' > /dev/null
sleep 2

# Current version is the first "prior" version - get it from endpoint
PRIOR=$(curl -sLk -XGET https://localhost/api/ver/ | jq -r .version)
VERSIONS=()
# Use Python Script to create array of versions that have to be installed
# versions between current and the latest
mapfile -t VERSIONS < <(python3 $CBOX_INSTALL_DIR/scripts/Automation/versions.py)
# GET env from local endpoint and extract it so we can keep it
ENV=$(curl -sLk localhost/api/ver/ | jq -r '.env')
TAG=${VERSIONS[-1]}
echo "Update to $TAG started across all intermediate versions."
source $CBOX_CONFIG_DIR/db.conf
for v in "${VERSIONS[@]}"
do
   backup $PRIOR
   echo "Install version $v"
   cd $CBOX_INSTALL_DIR
   git fetch
   cp $CBOX_CONFIG_DIR/.env.ls /var/lib/cbox/backup/.env.ls
   cp $CBOX_CONFIG_DIR/.env.es /var/lib/cbox/backup/.env.es
   git checkout -f $v >/dev/null 2>&1
   blackbox_postdeploy
   # Restore Memory Settings for JVM
   cp /var/lib/cbox/backup/.env.ls $CBOX_CONFIG_DIR/.env.ls
   cp /var/lib/cbox/backup/.env.es $CBOX_CONFIG_DIR/.env.es
   echo "Run update instructions from version $v"
   sed -i "3s/.*/TAG=$v/g" $CBOX_INSTALL_DIR/update-patch.sh
   chmod +x $CBOX_INSTALL_DIR/update-patch.sh
   $CBOX_INSTALL_DIR/update-patch.sh
   if  [[ ! $? -eq 0 ]]; then
     echo "Update to $v failed"
     # Notify API that we're starting to roll back
     curl -sLk -XPOST https://localhost/api/update/status/ -H "Content-Type: application/json" -d '{"status":"rollback-running"}' > /dev/null
     rollback $PRIOR $v
   fi
   # successfully updated version
   # pack and store backup
   tar -C /var/lib/cbox -cvpzf /var/lib/cbox/update_backup_$PRIOR.tar.gz backup/
   # clear backup folder
   rm -rf /var/lib/cbox/backup/*
   # delete backups older than 3 months
   find /var/lib/cbox/ -type f -name "update_backup_*.tar.gz" -mtime +90 -delete
   # the PRIOR is now the successfully installed version
   PRIOR=$v
done
echo "Update completed on $TAG."
# set version in file
echo "VERSION=$TAG" > /var/lib/cbox/VERSION
echo "CBOX_ENV=$ENV" >> /var/lib/cbox/VERSION
# Notify API that we're finished
curl -sLk -XPOST https://localhost/api/update/status/ -H "Content-Type: application/json" -d '{"status":"successful"}' > /dev/null
# Prepare new update.sh for next update
chown cboxadmin:cboxadmin $CBOX_INSTALL_DIR/scripts/Automation/update.sh
chmod +x $CBOX_INSTALL_DIR/scripts/Automation/update.sh
sleep 15 # sleep for API <-> Webbrowser communication
curl -sLk -XDELETE https://localhost/api/update/status/ > /dev/null
exit 0
