#!/bin/bash
CURRENT=$(df /data | grep /data | awk '{ print $5}' | sed 's/%//g')
THRESHOLD=66

if [ "$CURRENT" -gt "$THRESHOLD" ] ; then
  echo -e "Stockage sur disque dur CBox chez le Client $CLIENT \n/les données sont $CURRENT% affectées."
fi
