#!/bin/bash
set -e
# Log file to use
# Create path if allowed or do NOP
mkdir -p /var/log/cbox/1stLevelRepair || :
LOG_DIR="/var/log/cbox/1stLevelRepair"
if [[ ! -w $LOG_DIR ]]; then
  LOG_DIR="$HOME"
fi

LOG=$LOG_DIR/restart_service.log

# Do not use interactive debian frontend.
export DEBIAN_FRONTEND=noninteractive

# Forward fd2 to the console
# exec 2>&1
# Forward fd1 to $LOG
exec 2>&1 1>>${LOG}
echo -n "Stopping CBox Service.. " 1>&2
sudo systemctl stop cbox.service
echo "[ DONE ]" 1>&2
echo -n "Starting CBox Service.. " 1>&2
sudo systemctl start cbox.service
echo "[ DONE ]" 1>&2
