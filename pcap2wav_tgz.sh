
OPT=opt
PW_ROOT=$OPT/pcap2wav

make
mkdir $OPT
mkdir $PW_ROOT
mkdir $PW_ROOT/config
cp -a xplico $PW_ROOT
cp -a videosnarf $PW_ROOT
cp -a modules $PW_ROOT
cp -a config $PW_ROOT
cp -a pcap2wavd.sh $PW_ROOT
cp -a system/pcap2wav $PW_ROOT/www

tar czvf pcap2wav.tgz $OPT
rm -rf $OPT