# Imprint POC web (SpaceY + ZebraPal + ModSecurity)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       apache2 libapache2-mod-php8.1 php8.1-curl php8.1-mbstring libphp-phpmailer \
       libapache2-mod-security2 modsecurity-crs openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ModSecurity config (DetectionOnly)
COPY waf/modsecurity.conf /etc/modsecurity/modsecurity.conf

# Sites (zebrapal gets the shared fingerprint scripts and includes)
COPY webpage_raw/spacey /var/www/spacey
COPY webpage_raw/zebrapal /var/www/zebrapal
COPY webpage_modules/fingerprint_scripts /var/www/zebrapal/fingerprint_scripts
COPY webpage_modules/includes /var/www/zebrapal/includes
COPY webpage_modules/assets /var/www/zebrapal/assets
COPY webpage_raw/apache2_conf/spacey.conf webpage_raw/apache2_conf/zebrapal.conf /etc/apache2/sites-available/

# Imprint PHP library
COPY scripts/imprint/env.php scripts/imprint/imprint_client.php /opt/imprint/
COPY docker/web/entrypoint.sh /usr/local/bin/imprint-web-entrypoint

RUN sed -i 's/\r$//' /usr/local/bin/imprint-web-entrypoint /etc/apache2/sites-available/*.conf /etc/modsecurity/modsecurity.conf \
    && chmod 755 /usr/local/bin/imprint-web-entrypoint \
    && a2enmod rewrite ssl headers security2 php8.1 \
    && a2dissite 000-default \
    && a2ensite spacey zebrapal \
    && (grep -q '^Listen 8443' /etc/apache2/ports.conf || echo 'Listen 8443' >> /etc/apache2/ports.conf) \
    && echo 'ServerName localhost' > /etc/apache2/conf-enabled/servername.conf \
    && chown -R www-data:www-data /var/www/spacey /var/www/zebrapal

EXPOSE 80 443 8443
ENTRYPOINT ["imprint-web-entrypoint"]
CMD ["apache2ctl", "-D", "FOREGROUND"]
