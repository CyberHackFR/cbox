#!/bin/bash
# Creates self signed certificate in a interactive session using
# default values from cbox-ssl.conf
# Key is without a passphrase
openssl req -config ../../config/ssl/cbox-ssl.conf -new -x509 -sha256 -newkey rsa:4096 -nodes -keyout ../../config/secrets/cbox.key.pem -days 365 -out ../../config/ssl/cbox.cert.pem

chmod 600 ../../config/secrets/cbox.key.pem
chmod 644 ../../config/ssl/cbox.cert.pem
