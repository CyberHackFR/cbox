FROM securecompliance/gvm:20.08-v2
#20.08-v1 oldtag

ADD etc/ /etc/openvas/
ADD scripts/ /root/

RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -  && \
    apt-get update && \
    apt-get install -y python3-venv && \
    rm -rf /var/cache/apk/* && \
    chmod +x /root/insertconfig.sh && \
    chmod +x /root/start.sh && \
    chmod +x /root/update.sh && \
    chmod +x /root/vulnwhisp.sh

EXPOSE 9392
EXPOSE 9390
HEALTHCHECK --retries=10 CMD curl -sLk -XGET 'https://127.0.0.1:9392'
CMD /root/start.sh
