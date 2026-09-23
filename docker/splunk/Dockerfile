# Imprint POC Splunk
FROM splunk/splunk:10.4.3

# Apps are copied into /opt/splunk/etc/apps on start (etc is a volume)
USER root
COPY splunk_app/imprint /opt/imprint-splunk-apps/imprint
COPY docker/splunk/imprint_poc /opt/imprint-splunk-apps/imprint_poc
# Honeypot dashboard (POC example) and its menu entry added to the Imprint app
COPY docker/splunk/views/imprint_honeypot.xml /opt/imprint-splunk-apps/imprint/default/data/ui/views/
COPY docker/splunk/nav/default.xml /opt/imprint-splunk-apps/imprint/default/data/ui/nav/default.xml
COPY docker/splunk/entrypoint.sh /usr/local/bin/imprint-splunk-entrypoint
RUN find /opt/imprint-splunk-apps /usr/local/bin/imprint-splunk-entrypoint -type f -exec sed -i 's/\r$//' {} + \
    && chmod 755 /opt/imprint-splunk-apps/imprint/bin/*.py /usr/local/bin/imprint-splunk-entrypoint \
    && chown -R splunk:splunk /opt/imprint-splunk-apps
USER ansible

ENTRYPOINT ["/usr/local/bin/imprint-splunk-entrypoint"]
CMD ["start-service"]
