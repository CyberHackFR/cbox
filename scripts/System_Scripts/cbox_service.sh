#!/bin/bash
source /etc/cbox/modules.conf
# Construct set of compose files, depending on enabled modules
COMPOSE_FILES="-f $CBOX_INSTALL_DIR/docker/cbox.yml"
if [ $CBox_WAZUH == "true" ]; then
    COMPOSE_FILES="$COMPOSE_FILES -f $CBOX_INSTALL_DIR/docker/wazuh/wazuh.yml"
fi
if [ $1 == "up" ]
then
    
    # perform commands to set the service up
    # Stop and remove old container
    /usr/local/bin/docker-compose $COMPOSE_FILES down -v
    /usr/local/bin/docker-compose $COMPOSE_FILES rm -v
    /usr/local/bin/docker-compose $COMPOSE_FILES up --no-color --no-build --remove-orphans
    # Listen to the web named pipe.
    /bin/bash $CBOX_INSTALL_DIR/scripts/System_Scripts/listenNamedPipe.sh &
elif [ $1 == "down" ]
then
    # perform commands to set the service down
    /usr/local/bin/docker-compose $COMPOSE_FILES down -v
else
    echo "You have to submit up/down as the first parameter to the CBox service script."
    exit 1
fi
