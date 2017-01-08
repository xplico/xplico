#!/bin/bash

# pcap2wav daemon

# path
export PATH=$PATH:/opt/pcap2wav/

# webserver root dir full path of "server/php/files" sub-dir
www_dir=/opt/pcap2wav/www/server/php/files

cfg_file="/opt/pcap2wav/config/pcap2wav.cfg"

while true; do
    for dr in $www_dir/*; do
        for fl in $dr/pcap/*; do
            if [ -f "$fl" ]; then
                
                # work dir configuration file
                ncfg=$dr"/c.cfg";
                cp $cfg_file $ncfg
                `echo "DISPATCH_DECODE_DIR="$dr >> $ncfg`;
                
                # launch Xplico
                cd /opt/pcap2wav; ./xplico -c $ncfg -m pcap  -f "$fl"
                
                rm -f "$fl" $ncfg
            fi
        done
    done
    sleep 2
done

