#!/bin/bash

wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz
tar -xf GeoLite2-City.tar.gz --wildcards --no-anchored '*.mmdb'
tar -xf GeoLite2-Country.tar.gz --wildcards --no-anchored '*.mmdb'
mv */*.mmdb /tmp
rm -rf GeoLite2-C*
mv /tmp/*.mmdb .

