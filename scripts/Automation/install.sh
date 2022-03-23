#!/bin/bash
set -e

# Initial information

echo -e "_________        ___.               __________              
         \_   ___ \___.__.\_ |__   __________\______   \ _______  ___
         /    \  \<   |  | | __ \_/ __ \_  __ \    |  _//  _ \  \/  /
         \     \___\___  | | \_\ \  ___/|  | \/    |   (  <_> >    < 
          \______  / ____| |___  /\___  >__|  |______  /\____/__/\_ \
                 \/\/          \/     \/             \/            \/



Disclaimer:
This script will install the CyberBox on this system.
By running the script you confirm to know what you are doing:
1. New packages will be installed.
2. A new folder called '/data' will be created in your root directory.
3. A new sudo user called 'cboxadmin' will be created on this system.
4. The CBox service will be enabled.

#############################################
Usage:
sudo $0
Options:
sudo $0 --manual - All available tags will be available for install - All of them.\n"
# Check for root

if [ "$(whoami)" != "root" ];
  then
    echo "#####################################################
### Installation Requires Root. Please use 'sudo' ###
#####################################################"
    exit 1
  else
    echo "#####################################################
###    Starting CBox installation...      ###
#####################################################"
fi

# Log file to use
# Create path if allowed or do NOP
mkdir -p /var/log/cbox/ || :

# Determine log dir, if writable use /var/log else user's home.
LOG_DIR="/var/log/cbox"
if [[ ! -w $LOG_DIR ]]; then
  LOG_DIR="$HOME"
fi

sudo chown -R root:44269 $LOG_DIR
sudo chmod 760 -R $LOG_DIR

FULL_LOG=$LOG_DIR/install.log
ERROR_LOG=$LOG_DIR/install.err.log

# Do not use interactive debian frontend.
export DEBIAN_FRONTEND=noninteractive

# Get the actual dir of the installation script.
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
INSTALL_DIR="/opt/cbox"
CONFIG_DIR="/etc/cbox"
# TODO: Temp
TAG=0.0.1
# Forward fd3 to the console
# exec 3>&1
# Forward stderr to $ERROR_LOG
# exec 2> >(tee "$ERROR_LOG")
# Forward stdout to $FULL_LOG
# exec > >(tee "$FULL_LOG")
exec 3>&1 1>>${FULL_LOG} 2>>$ERROR_LOG
##################################################
#                                                #
# Functions                                      #
#                                                #
##################################################

# This needs toilet to be installed
function banner {
  toilet -f ivrit "$1" 1>&3
}

function testNet() {
  # Returns 0 for successful internet connection and dns resolution , 1 else
  ping -q -c 1 -W 1 $1 >/dev/null;
  return $?
}
function delete_If_Exists(){
  # Helper to delete files and directories if they exist
  if [ -d $1 ]; then
    # Directory to remove
    sudo rm $1 -r
  fi
  if [ -f $1 ]; then
    # File to remove
    sudo rm $1
  fi
}
function waitForNet() {
  # use argument or default value of google.com
  HOST=${1:-"google.com"}
  while ! testNet $HOST; do
    # while testNet returns non zero value
    echo "No internet connectivity or dns resolution of $HOST, sleeping for 15s" 1>&2
    sleep 15s
    echo /etc/resolv.conf | grep 'nameserver' || echo "nameserver 8.8.8.8" > /etc/resolv.conf && echo "Empty /etc/resolv.conf/ -> inserting 8.8.8.8" 1>&2
  done
}

# Helper to check if a service exists on the system
function service_exists() {
    local n=$1
    if [[ $(systemctl list-units --all -t service --full --no-legend "$n.service" | cut -f1 -d' ') == $n.service ]]; then
        return 0
    else
        return 1
    fi
}
function create_and_changePermission() {
  sudo touch $1
  sudo chown -R root:44269 $1
  sudo chmod 760 -R $1
}
function genSecret() {
    echo `tr -dc A-Za-z0-9 </dev/urandom | head -c 24`
}

# Lets make sure some basic tools are available
CURL=$(which curl) || echo ""
WGET=$(which wget) || echo ""
SUDO=$(which sudo) || echo ""
TOILET=$(which toilet) || echo ""
if [ "$CURL" == "" ] || [ "$WGET" == "" ] || [ "$SUDO" == "" ] || [ "$TOILET" == "" ]
  then
    waitForNet
    echo "### Installing deps for apt-fast"
    sudo apt -y update
    sudo apt -y install curl wget sudo toilet figlet
fi

##################################################
#                                                #
# Dependencies                                   #
#                                                #
##################################################
banner "Dependencies ..."

echo -n "Creating the /data directory.. " 1>&3
# Create the /data directory if it does not exist and make it readable
sudo mkdir -p /data
sudo chown root:root /data
sudo chmod 777 /data
sudo mkdir -p /data/suricata/
sudo touch /data/suricata/eve.json
echo "[ OK ]" 1>&3

# Create update log
sudo touch /var/log/cbox/update.log

# Lets install apt-fast for quick package installation
waitForNet
echo -n "Installing apt-fast.. " 1>&3
sudo /bin/bash -c "$(curl -sL https://raw.githubusercontent.com/ilikenwf/apt-fast/master/quick-install.sh)"
echo "[ OK ]" 1>&3
# Remove services, that might be present, but are not needed.
echo -n "Removing standard services.. " 1>&3

# Disable and remove Apache2
if service_exists apache2; then
    sudo service apache2 disable
    sudo apt-fast remove --purge -y apache2
fi

# Disable and remove Nginx
if service_exists nginx; then
    sudo service nginx disable
    sudo apt-fast remove --purge -y nginx
fi

# Disable systemd-resolved
if service_exists systemd-resolved; then
    sudo systemctl disable systemd-resolved || :
fi
echo "[ OK ]" 1>&3

echo -n "Checking for an old version of CBox and stopping.. " 1>&3
# Remove old CBox service
if service_exists cbox; then
    sudo systemctl stop cbox.service
fi
echo "[ OK ]" 1>&3
# Lets install all dependencies
waitForNet
echo -n "Downloading and installing dependencies. This may take some time.. " 1>&3
sudo apt-fast install -y unattended-upgrades curl python python3 python3-pip python3-venv git git-lfs jq docker.io apt-transport-https msmtp msmtp-mta landscape-common unzip postgresql-client resolvconf boxes lolcat secure-delete
echo "[ OK ]" 1>&3

echo -n "Enabling git lfs.. " 1>&3
# Check if .git exists in /tmp/cbox - if it doesn't then not initial install and skip
git lfs install --skip-smudge
echo "[ OK ]" 1>&3

echo -n "Installing Python3 modules from PyPi.. " 1>&3
pip3 install semver requests
echo "[ OK ]" 1>&3

echo -n "Installing Docker-Compose.. " 1>&3
# Remove old docker-compose if found
delete_If_Exists /usr/local/bin/docker-compose
curl -sL "https://github.com/docker/compose/releases/download/v2.2.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
echo "[ OK ]" 1>&3

# Change to repo root path
cd $SCRIPTDIR/../../
echo -n "Sourcing secret files.. " 1>&3
source config/secrets/secrets.conf
source config/secrets/db.conf
source config/secrets/web.conf
source config/secrets/openvas.conf
echo "[ OK ]" 1>&3

# TODO: Find solution with ip2location for not downlod everytime
echo -n "Checking and replacing default secrets.. " 1>&3
if [[ -z $POSTGRES_PASSWORD || "$POSTGRES_PASSWORD" == "CHANGEME" ]]; then
    POSTGRES_PASSWORD=`genSecret`
fi
# TODO: Find solution!!!
# if [[ -z $IP2TOKEN || "$IP2TOKEN" == "GET_ME_FROM_IP2LOCATION.COM" ]]; then
#     echo "[ FAIL ]" 1>&3
#     echo "Installation requires a token for IP2Location. Go to https://lite.ip2location.com now and enter an API token below." 1>&3 
#     echo "Tokens are not validated on this end. Make sure the entered token is correct, otherwise the installation WILL fail. Token:" 1>&3 
#     read IP2TOKEN
# fi
if [[ -z $SECRET_KEY || "$SECRET_KEY" == "CHANGEME" ]]; then
    SECRET_KEY=`genSecret`
fi
if [[ -z $OPENVAS_PASS || "$OPENVAS_PASS" == "CHANGEME" ]]; then
    OPENVAS_PASS=`genSecret`
fi
echo "[ OK ]" 1>&3

# Create the user $HOST_USER only if he does not exist
# The used password is known to the whole dev-team
echo -n "Creating CyberBox user on the host.. " 1>&3
id -u $HOST_USER &>/dev/null || sudo useradd -m -p $HOST_PASS -s /bin/bash $HOST_USER
sudo usermod -aG sudo $HOST_USER
grep -qxF "$HOST_USER ALL=(ALL) NOPASSWD: ALL" /etc/sudoers || echo "$HOST_USER ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
cat /etc/group | grep cyberhackbox &>/dev/null || sudo addgroup --gid 44269 cyberhackbox # Create group if it does not exist
id -G $HOST_USER | grep 44229 &>/dev/null || sudo usermod -a -G cyberhackbox $HOST_USER # Add HOST_USER to created group if not in it
echo "[ OK ]" 1>&3

echo -n "Creating the installation directory ($INSTALL_DIR).. " 1>&3
delete_If_Exists $INSTALL_DIR
sudo mkdir -p $INSTALL_DIR
sudo chown cboxadmin:cboxadmin $INSTALL_DIR
echo "[ OK ]" 1>&3

echo -n "Creating the configuration directory ($CONFIG_DIR).. " 1>&3
delete_If_Exists $CONFIG_DIR
sudo mkdir -p $CONFIG_DIR
sudo chown cboxadmin:cboxadmin $CONFIG_DIR
echo "[ OK ]" 1>&3

##################################################
#                                                #
# Tags                                           #
#                                                #
##################################################
# banner "Tags ..." # TODO: Tags for cbox

# # If manual isntallation, make all tags visible and choose the tag to install
# if [[ "$*" == *manual* ]]
# then
#   # --manual supplied => ask user which to install
#   # Fetch all TAGS as names
#   mapfile -t TAGS < <(curl -s -H "Accept: application/vnd.github.v3+json" \
#   https://api.github.com/repos/releases | jq -r .[].tag_name)

#   echo "Available tags:" 1>&3
#   printf '%s\n' "${TAGS[@]}" 1>&3
#   echo "Type tag to install:" 1>&3
#   read TAG
#   while [[ ! " ${TAGS[@]} " =~ " ${TAG} " ]]; do
#     echo "$TAG is not in ${TAGS[@]}. Try again." 1>&3
#     read TAG
#   done
#   echo "$TAG will be installed.. [ OK ]" 1>&3
# else
#   # not manual, install most recent and valid tag
#   TAG=$(curl -s -H "Accept: application/vnd.github.v3+json" \
#   https://api.github.com/repos/releases/latest | jq -r '.tag_name')
#   echo "Installing the most recent tag $TAG.. [ OK ]" 1>&3
# fi
# echo "Installing $TAG."
##################################################
#                                                #
# Clone Repository                               #
#                                                #
##################################################
banner "Repository ..."

echo -n "Downloading the repository @ $TAG" 1>&3
git clone --depth 1 --branch $TAG https://github.com/CyberHackFR/cbox.git $INSTALL_DIR
echo "[ OK ]" 1>&3

# Copy certificates over
echo -n "Creating selfsigned SSL certificate.. " 1>&3
sudo mkdir -p $CONFIG_DIR/certs
sudo openssl req -new -x509 -config $SCRIPTDIR/../../config/ssl/cbox-ssl.conf \
    -subj "/C=FR/ST=LOT/L=Cahors/O=CyberHack/OU=IT Security/CN=CBox/emailAddress=box@cyberhack.fr" \
    -newkey rsa:4096 -days 365 -nodes \
    -keyout $CONFIG_DIR/certs/cbox.key.pem  -out $CONFIG_DIR/certs/cbox.cert.pem
sudo chown -R root:44269 $CONFIG_DIR/certs
sudo chmod 770 -R $CONFIG_DIR/certs
echo "[ OK ]" 1>&3

# Copy the smtp.conf to the config directory
echo -n "Enabling SMTP config.. " 1>&3
sudo cp $SCRIPTDIR/../../config/secrets/smtp.conf $CONFIG_DIR/smtp.conf
echo "[ OK ]" 1>&3

##################################################
#                                                #
# Docker Volumes                                 #
#                                                #
##################################################
sudo systemctl start docker
banner "Volumes ..."

echo -n "Creating volumes and setting permissions.. " 1>&3

echo -n "data:" 1>&1
# Check if each volume exists before creating them; Skip if already created
# Setup data volume
sudo docker volume create --driver local --opt type=none --opt device=/data --opt o=bind data
sudo chown -R root:44269 /data
sudo chmod 760 -R /data
echo " [ DONE ] " 1>&1

# Setup CBox volume
echo -n "varlib_cbox:" 1>&1
delete_If_Exists /var/lib/cbox_openvas/
sudo mkdir -p /var/lib/cbox
sudo chown root:root /var/lib/cbox
sudo chmod -R 777 /var/lib/cbox
sudo docker volume create --driver local --opt type=none --opt device=/var/lib/cbox/ --opt o=bind varlib_cbox
sudo chown -R root:44269 /var/lib/cbox
sudo chmod 760 -R /var/lib/cbox
echo " [ DONE ] " 1>&1

# Setup PostgreSQL volume
echo -n "varlib_postgresql:" 1>&1
delete_If_Exists /var/lib/postgresql
sudo mkdir -p /var/lib/postgresql/data
sudo docker volume create --driver local --opt type=none --opt device=/var/lib/postgresql/data --opt o=bind varlib_postgresql
sudo chown -R root:44269 /var/lib/postgresql/data
sudo chmod 760 -R /var/lib/postgresql/data
echo " [ DONE ] " 1>&1

# Setup Suricata Rule volume
echo -n "varlib_suricata:" 1>&1
sudo mkdir -p /var/lib/cbox_suricata_rules/
sudo chown root:root /var/lib/cbox_suricata_rules/
sudo chmod -R 777 /var/lib/cbox_suricata_rules/
sudo docker volume create --driver local --opt type=none --opt device=/var/lib/cbox_suricata_rules/ --opt o=bind varlib_suricata
echo " [ DONE ] " 1>&1

# Setup CyberBox Settings volume
echo -n "etccbox_logstash:" 1>&1
sudo mkdir -p $CONFIG_DIR/logstash
sudo cp -R $SCRIPTDIR/../../config/etc/logstash/* $CONFIG_DIR/logstash/
sudo chown root:root $CONFIG_DIR/logstash
sudo chmod -R 777 $CONFIG_DIR/logstash
sudo docker volume create --driver local --opt type=none --opt device=$CONFIG_DIR/logstash/ --opt o=bind etccbox_logstash
sudo chown -R root:44269 $CONFIG_DIR/logstash
sudo chmod 760 -R $CONFIG_DIR/logstash
echo " [ DONE ] " 1>&1

# Setup Logstash volume
echo -n "varlib_logstash:" 1>&1
delete_If_Exists /var/lib/logstash
sudo mkdir -p /var/lib/logstash
sudo mkdir -p /var/lib/logstash/openvas/
sudo chown root:root /var/lib/logstash
sudo chmod -R 777 /var/lib/logstash
sudo docker volume create --driver local --opt type=none --opt device=/var/lib/logstash/ --opt o=bind varlib_logstash
sudo chown -R root:44269 /var/lib/logstash
sudo chmod 760 -R /var/lib/logstash
echo " [ DONE ] " 1>&1

# Setup OpenVAS volume
echo -n "varlib_postgresql:" 1>&1
sudo mkdir -p /var/lib/cbox_openvas/
sudo chown root:root /var/lib/cbox_openvas/
sudo chmod -R 777 /var/lib/cbox_openvas/
sudo docker volume create --driver local --opt type=none --opt device=/var/lib/cbox_openvas/ --opt o=bind gvm-data
sudo chown -R root:root /var/lib/cbox_openvas
echo " [ DONE ] " 1>&1

# Setup Elasticsearch volume
sudo mkdir /data/elasticsearch -p
sudo mkdir /data/elasticsearch_backup/Snapshots -p
# Elasticsearch is somewhat special...
sudo chown -R 1000:0 /data/elasticsearch
sudo chown -R 1000:0 /data/elasticsearch_backup
sudo chmod 760 -R /data/elasticsearch
sudo chmod 760 -R /data/elasticsearch_backup

# Setup ElastAlert volume
echo -n "varlib_elastalert_rules:" 1>&1
sudo mkdir -p /var/lib/elastalert/rules
sudo chown root:root /var/lib/elastalert/rules
sudo chmod -R 777 /var/lib/elastalert/rules
sudo docker volume create --driver local --opt type=none --opt device=/var/lib/elastalert/rules --opt o=bind varlib_elastalert_rules
sudo chown -R root:44269 /var/lib/elastalert/rules
sudo chmod 760 -R /var/lib/elastalert/rules
echo " [ DONE ] " 1>&1

# Setup Wiki volume
echo -n "varlib_docs:" 1>&1
sudo mkdir -p /var/lib/cbox_docs
sudo chown root:root /var/lib/cbox_docs
sudo chmod -R 777 /var/lib/cbox_docs
sudo docker volume create --driver local --opt type=none --opt device=/var/lib/cbox_docs --opt o=bind varlib_docs
sudo chown -R root:44269 /var/lib/cbox_docs/
sudo chmod 760 -R /var/lib/cbox_docs/
echo " [ DONE ] " 1>&1

#Done with volumes
echo "[ OK ]" 1>&3

echo -n "Initializing important files and setting permissions.. " 1>&3
create_and_changePermission /var/lib/cbox/elastalert_smtp.yaml
create_and_changePermission $CONFIG_DIR/smtp.conf
create_and_changePermission /etc/ssl/certs/ca-certificates.crt
create_and_changePermission /var/lib/cbox/elastalert_smtp.yaml
create_and_changePermission $CONFIG_DIR/modules.conf
create_and_changePermission /etc/ssl/certs/CBox-SMTP.pem

echo "[ OK ]" 1>&3
##################################################
#                                                #
# Installing CyberBox                                 #
#                                                #
##################################################
banner "CyberBox ..."

echo -n "Setting environmental permissions.. " 1>&3
sudo mkdir -p /etc/netplan || :
sudo touch /etc/default/logstash || :
sudo touch /etc/environment || :
sudo chown -R root:44269 /etc/environment
sudo chmod 770 -R /etc/environment
sudo chown -R root:44269 /etc/default/logstash
sudo chmod 770 -R /etc/default/logstash
sudo chown -R root:44269 /etc/netplan
sudo chmod 770 -R /etc/netplan
echo " [ OK ]" 1>&3

echo -n "Setting hostname.. " 1>&3
hostname cbox
grep -qxF "127.0.0.1 cbox" /etc/hosts || echo "127.0.0.1 cbox" >> /etc/hosts
echo " [ OK ]" 1>&3

# Initially clone the Wiki repo
echo -n "Downloading documentation.. " 1>&3
# Delete already existing repository
delete_If_Exists /var/lib/cbox_docs
mkdir -p /var/lib/cbox_docs
cd /var/lib/cbox_docs
sudo git clone https://github.com/CyberHackFR/cbox-docs.git . # TODO: Change repository
echo " [ OK ]" 1>&3

echo -n "Configuring CBox.. " 1>&3
# Copy gollum config to wiki root
cp $SCRIPTDIR/../../docker/wiki/config.ru /var/lib/cbox_docs/config.ru

# Copy version file
cp $SCRIPTDIR/../../VERSION /var/lib/cbox/VERSION

# Copy config files
cd $SCRIPTDIR/../../
sudo cp config/secrets/* $CONFIG_DIR
sed -i "s/SECRET_KEY=.*$/SECRET_KEY=$SECRET_KEY/g" $CONFIG_DIR/web.conf
sed -i "s/DATABASE_URL=.*$/DATABASE_URL=postgresql:\/\/$POSTGRES_USER:$POSTGRES_PASSWORD@db:$POSTGRES_PORT\/$POSTGRES_DB/g" $CONFIG_DIR/web.conf
sed -i "s/POSTGRES_PASSWORD=.*$/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/g" $CONFIG_DIR/db.conf
#sed -i "s/IP2TOKEN=.*$/IP2TOKEN=$IP2TOKEN/g" $CONFIG_DIR/secrets.conf
sed -i "s/OPENVAS_PASS=.*$/OPENVAS_PASS=$OPENVAS_PASS/g" $CONFIG_DIR/openvas.conf
sudo cp config/etc/etc_files/* /etc/ -R || :
sudo cp config/secrets/msmtprc /etc/msmtprc
sudo chown root:44269 /etc/msmtprc
sudo chmod 770 /etc/msmtprc

# Create a folder for the alerting rules
sudo mkdir -p /var/lib/elastalert/rules

# Copy default elastalert smtp auth file
sudo cp $SCRIPTDIR/../../docker/elastalert/etc/elastalert/smtp_auth_file.yaml /var/lib/cbox/elastalert_smtp.yaml
echo " [ OK ]" 1>&3

echo -n "Setting system environment variables.. " 1>&3
set +e
IPINFO=$(ip a | grep -E "inet [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | grep -v "host lo")
IPINFO2=$(echo $IPINFO | grep -o -P '(?<=inet)((?!inet).)*(?=ens|eth|eno|enp)')
INT_IP=$(echo $IPINFO2 | sed 's/\/.*//')
grep -qxF  INT_IP=$INT_IP /etc/environment || echo INT_IP=$INT_IP >> /etc/environment
grep -qxF CBOX_CONFIG_DIR="$CONFIG_DIR" /etc/environment || echo CBOX_CONFIG_DIR="$CONFIG_DIR" | sudo tee -a /etc/environment
grep -qxF CBOX_INSTALL_DIR="$INSTALL_DIR" /etc/environment || echo CBOX_INSTALL_DIR="$INSTALL_DIR" | sudo tee -a /etc/environment
source /etc/environment
grep -qxF  INT_IP="$INT_IP" /etc/default/logstash || echo INT_IP="$INT_IP" >> /etc/default/logstash
grep -qxF CLIENT="NEWSYSTEM" /etc/default/logstash || echo CLIENT="NEWSYSTEM" | sudo tee -a /etc/default/logstash
set -e
echo " [ OK ] " 1>&3

echo -n "Setting network configuration and restarting network.. " 1>&3
# Find dhcp and remove everything after
sudo cp $SCRIPTDIR/../../config/etc/network/interfaces /etc/network/interfaces
sudo sed -i '/.*dhcp/q' /etc/network/interfaces

IF_MGMT=$(ip addr | cut -d ' ' -f2| tr ':' '\n' | awk NF | grep -v lo | head -n 1)
awk "NR==1,/auto ens[0-9]*/{sub(/auto ens[0-9]*/, \"auto $IF_MGMT\")} 1" /etc/network/interfaces > /tmp/cbox-ifaces
sudo mv /tmp/cbox-ifaces /etc/network/interfaces
awk "NR==1,/iface ens[0-9]* inet dhcp/{sub(/iface ens[0-9]* inet dhcp/, \"iface $IF_MGMT inet dhcp\")} 1" /etc/network/interfaces > /tmp/cbox-ifaces
echo 'dns-nameservers 127.0.0.53' >> /tmp/cbox-ifaces
sudo mv /tmp/cbox-ifaces /etc/network/interfaces

# Apply the new config without a restart
ip link set $IF_MGMT down
ip link set $IF_MGMT up

#Disable TCP Timestamps
grep -qxF "net.ipv4.tcp_timestamps = 0" /etc/sysctl.conf || echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf
sudo sysctl -p


# Set other interfaces
for iface in $(ip addr | cut -d ' ' -f2| tr ':' '\n' | awk NF | grep -v lo | tail -n +2)
do
  # dont apply this for tun0 or docker0
  if [[ "$iface" =~ ^(tun0|docker0)$ ]]; then
    continue;
  fi
  echo "auto $iface
    iface $iface inet manual
    up ifconfig $iface promisc up
    down ifconfig $iface promisc down" | sudo tee -a /etc/network/interfaces
  ip link set $iface down
  ip link set $iface up
done
echo " [ OK ] " 1>&3

echo -n "Setting the portmirror interface.. " 1>&3
# Find the portmirror interface for suricata
touch $CONFIG_DIR/.env.suri
IFACE=$(sudo ip addr | cut -d ' ' -f2 | tr ':' '\n' | awk NF | grep -v lo | sed -n 2p | cat)
echo "SURI_INTERFACE=$IFACE" > $CONFIG_DIR/.env.suri
echo " [ OK ] " 1>&3

echo -n "Enabling/Disabling Modules.. " 1>&3
# Remove old folder to avoid conflicts
sudo cp $SCRIPTDIR/../../config/etc/modules.conf $CONFIG_DIR/modules.conf
sudo chmod 444 $CONFIG_DIR/modules.conf
echo " [ OK ] " 1>&3

echo -n "Generating Wazuh Agent-Password.. " 1>&3
delete_If_Exists /var/lib/cbox/wazuh-authd.pass
strings /dev/urandom | grep -o '[[:alnum:]]' | head -n 14 | tr -d '\n' > /var/lib/cbox/wazuh-authd.pass
sudo chmod 755 /var/lib/cbox/wazuh-authd.pass
echo " [ OK ] " 1>&3

echo -n "CBox service setup and enabling.. " 1>&3
# Setup the new CBox Service and enable it
sudo mkdir -p /usr/bin/cbox/
sudo cp $SCRIPTDIR/../../scripts/System_Scripts/cbox_service.sh /usr/bin/cbox/cbox_service.sh
sudo chmod +x /usr/bin/cbox/cbox_service.sh
sudo cp $SCRIPTDIR/../../config/etc/systemd/cbox.service /etc/systemd/system/cbox.service
sudo systemctl daemon-reload
sudo systemctl enable cbox.service
echo " [ OK ] " 1>&3

##################################################
#                                                #
# Docker Setup                                   #
#                                                #
##################################################
banner "Docker ..."

echo -n "Detecting available memory and distributing it to the containers.. " 1>&3
# Detect rounded memory
MEM=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM=$(python3 -c "print($MEM/1024.0**2)")
# Give half of that to elasticsearch
ESMEM=$(python3 -c "print(int($MEM*0.5))")
sed "s/-Xms[[:digit:]]\+g -Xmx[[:digit:]]\+g/-Xms${ESMEM}g -Xmx${ESMEM}g/g" $SCRIPTDIR/../../docker/elasticsearch/.env.es > $CONFIG_DIR/.env.es
# and one quarter to logstash
LSMEM=$(python3 -c "print(int($MEM*0.25))")
sed "s/-Xms[[:digit:]]\+g -Xmx[[:digit:]]\+g/-Xms${LSMEM}g -Xmx${LSMEM}g/g" $SCRIPTDIR/../../docker/logstash/.env.ls > $CONFIG_DIR/.env.ls
echo " [ OK ] " 1>&3

echo -n "Downloading CBox software images. This may take a long time.. " 1>&3
# Login to docker registry
sudo docker-compose -f $SCRIPTDIR/../../docker/cbox.yml pull
sudo docker-compose -f $SCRIPTDIR/../../docker/wazuh/wazuh.yml pull
echo " [ OK ] " 1>&3

# TODO: fix this
# Download IP2Location DBs for the first time
# echo -n "Downloading and unpacking geolocation database. This may take some time.. " 1>&3
# cd /tmp/
# curl -sL "https://www.ip2location.com/download/?token=$IP2TOKEN&file=DB5LITEBIN" -o IP2LOCATION-LITE-DB5.BIN.zip
# curl -sL "https://www.ip2location.com/download/?token=$IP2TOKEN&file=DB5LITEBINIPV6" -o IP2LOCATION-LITE-DB5.IPV6.BIN.zip
#sudo unzip -o IP2LOCATION-LITE-DB5.BIN.zip
sudo cp /home/adminsec/IP2LOCATION-LITE-DB5.BIN /var/lib/cbox/IP2LOCATION-LITE-DB5.BIN
#sudo unzip -o IP2LOCATION-LITE-DB5.IPV6.BIN.zip
sudo cp /home/adminsec/IP2LOCATION-LITE-DB5.IPV6.BIN /var/lib/cbox/IP2LOCATION-LITE-DB5.IPV6.BIN
echo " [ OK ] " 1>&3


# Filter Functionality
echo -n "Setting up CBox Filters.. " 1>&3
sudo touch /var/lib/cbox/15_logstash_suppress.conf
sudo touch /var/lib/cbox/suricata_suppress.bpf
sudo chmod -R 777 /var/lib/cbox/
echo " [ OK ] " 1>&3

echo -n "Making scripts executable.. " 1>&3
chmod +x -R $INSTALL_DIR/scripts
echo " [ OK ] " 1>&3

echo -n "Enabling CBox internal DNS server.. " 1>&3
# DNSMasq Setup
sudo systemctl enable resolvconf.service
echo "nameserver 127.0.0.1" > /etc/resolvconf/resolv.conf.d/head
sudo cp $SCRIPTDIR/../../docker/dnsmasq/resolv.personal /var/lib/cbox/resolv.personal
# Fix DNS resolv permission
sudo chown root:44269 /var/lib/cbox/resolv.personal
sudo chmod 770 /var/lib/cbox/resolv.personal
sudo systemctl stop systemd-resolved
sudo systemctl start resolvconf.service
sudo resolvconf --enable-updates
sudo resolvconf -u
echo " [ OK ] " 1>&3

##################################################
#                                                #
# CyberBox start                                 #
#                                                #
##################################################
banner "Starting CyberBox..."

sudo systemctl start cbox


echo -n "Waiting for Elasticsearch to become available.. " 1>&3
sudo $SCRIPTDIR/../../scripts/System_Scripts/wait-for-healthy-container.sh elasticsearch
echo " [ OK ] " 1>&3

echo -n "Installing the scores index.. " 1>&3
sleep 5
# Install the scores index

sudo docker exec core4s /bin/bash /core4s/scripts/Automation/score_calculation/install_index.sh
echo " [ OK ] " 1>&3

echo -n "Installing new cronjobs.. " 1>&3
cd $SCRIPTDIR/../../config/crontab
su - cboxadmin -c "crontab $SCRIPTDIR/../../config/crontab/cboxadmin.crontab"
echo " [ OK ] " 1>&3

sudo systemctl daemon-reload

#Ignore own INT_IP
echo -n "Enabling filter to ignore own IP.. " 1>&3
sudo $SCRIPTDIR/../../scripts/System_Scripts/wait-for-healthy-container.sh db
echo "INSERT INTO blocks_by_bpffilter(src_ip, src_port, dst_ip, dst_port, proto) VALUES ('"$INT_IP"',0,'0.0.0.0',0,'');" | PGPASSWORD=$POSTGRES_PASSWORD PGUSER=$POSTGRES_USER psql postgres://localhost/cbox_db
echo "INSERT INTO blocks_by_bpffilter(src_ip, src_port, dst_ip, dst_port, proto) VALUES ('0.0.0.0',0,'"$INT_IP"',0,'');" | PGPASSWORD=$POSTGRES_PASSWORD PGUSER=$POSTGRES_USER psql postgres://localhost/cbox_db
echo " [ OK ] " 1>&3

echo -n "Waiting for Kibana to become available.. " 1>&3
sleep 30
sudo $SCRIPTDIR/../../scripts/System_Scripts/wait-for-healthy-container.sh kibana 600 && echo -n " [ OK  " 1>&3 || echo -n " [ NOT OK " 1>&3
sleep 30
sudo $SCRIPTDIR/../../scripts/System_Scripts/wait-for-healthy-container.sh kibana 600 && echo "  OK ] " 1>&3 || echo "  NOT OK ] " 1>&3

# Import Dashboard

echo -n "Installing Dashboards und Patterns.. " 1>&3
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/Accueil/Accueil.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/SIEM/SIEM-Alarme.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/SIEM/SIEM-ASN.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/SIEM/SIEM-DNS.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/SIEM/SIEM-HTTP.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/SIEM/SIEM-ProtocolesEtServices.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/SIEM/SIEM-SocialMedia.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/SIEM/SIEM-Apercu.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/Reseau/Presentation-Reseau.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/Reseau/Reseau-GeoIPetASN.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/Reseau/Flux-Donnees.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/Vulnerabilite/Details-Vulnerabilite.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/Vulnerabilite/Historique-Vulnerabilites.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/Vulnerabilite/Apercu-Vulnerabilite.ndjson
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/System/docker.ndjson

# Installiere Suricata Index Pattern
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/Patterns/suricata.ndjson

# Installiere Scores Index Pattern
curl -s -X POST "localhost:5601/kibana/api/saved_objects/_import?overwrite=true" -H "kbn-xsrf: true" --form file=@$SCRIPTDIR/../../config/dashboards/Patterns/scores.ndjson

# Create initial VulnWhisperer index
curl -XPUT "localhost:9200/logstash-vulnwhisperer-$(date +%Y.%m)"
echo " [ OK ] " 1>&3

toilet -f ivrit 'Ready!' | boxes -d cat -a hc -p h8 | /usr/games/lolcat
if [[ "$*" == *runner* ]]; then
# If in a runner environment exit now (successfully)
  exit 0
fi

echo -n "Activating unattended (automatic) Ubuntu upgrades.. " 1>&3
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo " [ OK ] " 1>&3

echo -n "Downloading Wazuh clients.. " 1>&3
# Download wazuh clients
sudo docker exec core4s /bin/bash /core4s/scripts/Automation/download_wazuh_clients.sh 3.12.3
echo " [ OK ] " 1>&3

echo -n "Updating tools. This may take a very long time.. " 1>&3
sudo docker container restart suricata
sleep 80
sudo docker exec suricata /root/scripts/update.sh
sleep 80
echo "[ suricata ] " 1>&3

echo -n "Cleaning up.. " 1>&3
sudo apt-fast autoremove -y
echo " [ OK ] " 1>&3

echo "The following secrets were used:" 1>&3
echo "Flask SECRET_KEY: $SECRET_KEY" 1>&3
echo "Postgres: $POSTGRES_USER:$POSTGRES_PASSWORD" 1>&3
#echo "IP2Location API Key: $IP2TOKEN" 1>&3
echo "OpenVAS Password: $OPENVAS_PASS" 1>&3

echo "CyberBox.. [ READY ]" | /usr/games/lolcat 1>&3
