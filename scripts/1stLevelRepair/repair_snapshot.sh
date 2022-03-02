#$1 contains name of the snapshot to restore
snaplocation="/var/lib/cbox/snapshots"
#check if snap has .zip ending or not
snap="$snaplocation/$1"
directory="${1%.*}"
tempDir="/tmp"
snapDir="$tempDir/$directory"
#Unzip snapshot
sudo unzip $snap -d $tempDir
#check version for equality
if ! cmp -s /var/lib/cbox/VERSION $snapDir/VERSION
then
  #versions not equal, exit
  exit 1
fi

#move saved files and change permissions
sudo cp -rf $snapDir/etc /
sudo cp -rf $snapDir/var /

#### /etc/cbox ####
sudo chown root:root /etc/cbox/
sudo chmod -R 777 /etc/cbox/
sudo chown -R root:44269 /etc/cbox/logstash
sudo chmod 760 -R /etc/cbox/logstash

#### /var/lib/cbox ####
sudo chown root:root /var/lib/cbox
sudo chmod -R 777 /var/lib/cbox

#### /var/lib/postgresql ####
sudo chown -R root:44269 /var/lib/postgresql/data
sudo chmod 760 -R /var/lib/postgresql/data

#### /var/lib/cbox_suricata_rules ####
sudo chown root:root /var/lib/cbox_suricata_rules/
sudo chmod -R 777 /var/lib/cbox_suricata_rules/

#### /var/lib/logstash ####
sudo chown root:root /var/lib/logstash
sudo chmod -R 777 /var/lib/logstash

#### /var/lib/elastalert ####
sudo chown root:root /var/lib/elastalert/rules
sudo chmod -R 777 /var/lib/elastalert/rules

#### /var/lib/cbox_docs ####
sudo chown root:root /var/lib/cbox_docs
sudo chmod -R 777 /var/lib/cbox_docs

sudo rm $snapDir -r
