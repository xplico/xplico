#!/usr/bin/php -q
<?php
  /*
   Copyright (c) 2007-2011 Gianluca Costa
   
   Author: Gianluca Costa, 2007-2011
   g.costa@xplico.org
   
   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
  */

if ($argc != 3) {
    echo "Usage:  ".$argv[0]." <xml_file> <output_file>\n\n";
    die();
}
$xml = simplexml_load_file($argv[1]);
if ($xml === FALSE) {
    echo "Error: ".$argv[1]." isn't a XML file\n";
    die();
}

$filtr = null;

foreach($xml->flow as $flow) {
    foreach($flow->frame as $frame) {
        if ($frame->frm_type == 'tcp') {
            foreach($frame as $prop) {
                if ($prop->name == 'tcp.srcport') {
                    $src_tcp_port = $prop->value;
                }
                else if ($prop->name == 'tcp.dstport') {
                    $dst_tcp_port = $prop->value;
                }
            }
        }
        else if ($frame->frm_type == 'udp') {
            foreach($frame as $prop) {
                if ($prop->name == 'udp.srcport') {
                    $src_udp_port = $prop->value;
                }
                else if ($prop->name == 'udp.dstport') {
                    $dst_udp_port = $prop->value;
                }
            }
        }
        else if ($frame->frm_type == 'ip') {
            foreach($frame as $prop) {
                if ($prop->name == 'ip.src') {
                    $src_ip = $prop->value;
                }
                else if ($prop->name == 'ip.dst') {
                    $dst_ip = $prop->value;
                }
            }
        }
        else if ($frame->frm_type == 'ipv6') {
            foreach($frame as $prop) {
                if ($prop->name == 'ipv6.src') {
                    $src_ipv6 = $prop->value;
                }
                else if ($prop->name == 'ipv6.dst') {
                    $dst_ipv6 = $prop->value;
                }
            }
        }
        else if ($frame->frm_type == 'pcapf') {
            foreach($frame as $prop) {
                if ($prop->name == 'pcapf.file') {
                    $pcap_file = $prop->value;
                }
            }
        }
        else if ($frame->frm_type == 'pol') {
            foreach($frame as $prop) {
                if ($prop->name == 'pol.file') {
                    $pcap_file = str_replace("/decode/", "/raw/", $prop->value);
                    if (!file_exists($pcap_file))
                        $pcap_file = str_replace("/raw/", "/fault/", $prop->value);
                }
            }
        }
    }
    if ($filtr != null)
        $filtr .= " or ";
    if (isset($src_tcp_port)) {
        if (isset($src_ip)) {
            $filtr .= "(ip.addr==".$src_ip." and ip.addr==".$dst_ip." and tcp.port==".$src_tcp_port." and tcp.port==".$dst_tcp_port.")";
        }
        else {
            $filtr .= "(tcp.port==".$src_tcp_port." and tcp.port==".$dst_tcp_port.")";
        }
    }
    else if (isset($src_udp_port)) {
        if (isset($src_ip)) {
            $filtr .= "(ip.addr==".$src_ip." and ip.addr==".$dst_ip." and udp.port==".$src_udp_port." and udp.port==".$dst_udp_port.")";
        }
        else {
            $filtr .= "(udp.port==".$src_udp_port." and udp.port==".$dst_udp_port.")";
        }
    }
    else
        $filtr .= "(ip.addr==".$src_ip." and ip.addr==".$dst_ip.")";
    unset($src_tcp_port);
    unset($src_udp_port);
}

$cmd = "tshark -n -r \"".$pcap_file."\" -R \"".$filtr."\" -w ".$argv[2];

system($cmd);
echo "Pcap file: ".$pcap_file."\n";
echo "Filter: ".$filtr."\n";
echo "Cmd line: ".$cmd."\n";

?>
