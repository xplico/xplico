# General Information

Xplico is a Network Forensic Analisys Tool NFAT, for Unix and Unix-like operating systems.  It uses libpcap, a packet capture and filtering library.


The official home of Xplico is

    http://www.xplico.org

The latest distribution can be found in the subdirectory

    http://www.xplico.org/download


# Installation

Xplico is known to compile and run on the following systems:
  * Linux (2.4 and later kernels, various distributions)
  * CPU taget: x86 multicore (Xplico use all cpu)
    * ARM
    * XScale


Full installation instructions can be found in the INSTALL file.
         

# Usage

We describe here only console-mode modality, if you use Web interface then you have to see INSTALL 
and with root permision run /opt/xplico/script/sqlite_demo.sh.

Xplico in console-mode permit you to decode a single pcap file, directory of pcap files or decode in 
realtime from an ethernet interface (eth0, eth1, ...).
To select the input type you have to use -m option. The '-m' option permit you to load a particular 
xplico capture interface (capture-module).
The possible capture interfaces are 'pcap' and 'rltm'. If you run "./xplico -h -m pcap" you have an 
help of use of pcap interface, obviously "./xplico -h -m rltm' give you an help to use realtime interface.
In console-mode all file extracted by xplico are placed in 'tmp/xplico/' direcory, every protocol has 
a particular directory, and inside this direcory you can find the decoding data.
For example:
 - if you have to decode test.pcap, you have to launch this command:
       ./xplico  -m pcap -f test.pcap
   at the end of decoding your files are in xdecode/ip/http, xdecode/ip/pop, xdecode/ip/smtp, ...
   and kml file (Google Earth) is in xdecode/ip/

 - if you have to decode a direcotry "/tmp/test" where inside there are many pcap files you have
   to launch this command:
       ./xplico  -m pcap -d /tmp/test
   at the end of decoding your files are in xdecode/ip/http, xdecode/ip/pop, xdecode/ip/smtp, ...
   and kml file (Google Earth) is in xdecode/ip/

 - if you have to decode eth0 in realtime the command is:
       ./xplico  -m rltm -i eth0
   to break acquisition: ^C. At the end of decoding (decoding is in realtime) your files are in xdecode/ip/http,
   xdecode/ip/pop, xdecode/ip/smtp, ...
   and kml file (Google Earth) is in xdecode/

Xplico has many decoding modules, these modules are in 'modules' directory, to enable or disable 
a module you have to modify the xplico.cfg file (by default in ./config/ directory)
The GeoMap file (kml) for Google Earth is updated every 30 sec.

./xplico -g give you a graph of relations between the dissectors.


# How to Report a Bug

Xplico still under constant development, so it is possible that you will
encounter a bug while using it. Please report bugs at bug@xplico.org .

# Disclaimer

There is no warranty, expressed or implied, associated with this product.
Use at your own risk.



Enjoy.
