# Called by web application - creates snapshot at /var/lib/cbox/snapshots/
# Create dir if not present
timestamp=$(date +%d-%m-%Y_%H-%M-%S)
#location to save snapshot to in the end
snaplocation="/var/lib/cbox/snapshots"
#location where snapshot first gets assembled - cannot contain copy targets
templocation="/tmp"
name="Snapshot-$timestamp"
folder="$templocation/$name"
#Create folder to store files temporarily
mkdir -p $folder

#helper to delete files
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

function copyFolder(){
  #Copy input folder to temporary folder
  outFolder=$folder/$1
  mkdir $outFolder -p
  cp -r $1 $folder/$1
}

#COPY FILES
#copy version to check if snapshot can be copied
cp /var/lib/cbox/VERSION $folder
copyFolder /etc/cbox
copyFolder /var/lib/cbox
delete_If_Exists $folder/var/lib/cbox/snapshots
copyFolder /var/lib/postgresql
copyFolder /var/lib/cbox_suricata_rules
copyFolder /var/lib/logstash
copyFolder /var/lib/elastalert
copyFolder /var/lib/cbox_docs


#create zip and remove snap_folder
cd $templocation
sudo zip -r $name.zip $name/
#move file to snaplocation and remove folder in temp location
sudo mv $name.zip $snaplocation
rm $folder -R
