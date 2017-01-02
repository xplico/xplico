<?php
  /* ***** BEGIN LICENSE BLOCK *****
   * Version: MPL 1.1/GPL 2.0/LGPL 2.1
   *
   * The contents of this file are subject to the Mozilla Public License
   * Version 1.1 (the "MPL"); you may not use this file except in
   * compliance with the MPL. You may obtain a copy of the MPL at
   * http://www.mozilla.org/MPL/
   *
   * Software distributed under the MPL is distributed on an "AS IS" basis,
   * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the MPL
   * for the specific language governing rights and limitations under the
   * MPL.
   *
   * The Original Code is Xplico Interface (XI).
   *
   * The Initial Developer of the Original Code is
   * Gianluca Costa <g.costa@xplico.org>
   * Portions created by the Initial Developer are Copyright (C) 2007
   * the Initial Developer. All Rights Reserved.
   *
   * Contributor(s):
   *
   * Alternatively, the contents of this file may be used under the terms of
   * either the GNU General Public License Version 2 or later (the "GPL"), or
   * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
   * in which case the provisions of the GPL or the LGPL are applicable instead
   * of those above. If you wish to allow use of your version of this file only
   * under the terms of either the GPL or the LGPL, and not to allow others to
   * use your version of this file under the terms of the MPL, indicate your
   * decision by deleting the provisions above and replace them with the notice
   * and other provisions required by the GPL or the LGPL. If you do not delete
   * the provisions above, a recipient may use your version of this file under
   * the terms of any one of the MPL, the GPL or the LGPL.
   *
   * ***** END LICENSE BLOCK ***** */

class Xml2PcapComponent extends Component
{
    var $someVar = null;
    var $controller = true;

    function startup(Controller $controller) {
        // This method takes a reference to the controller which is loading it.
        // Perform controller initialization here.
    }
    
    function doPcap($out_pcap, $xml_file) {
        // empty file... avoid error
        $fp = fopen($out_pcap, 'aw');
        fclose($fp);
        $filtr = null;
        $xml = simplexml_load_file($xml_file);
        if ($xml === FALSE) {
            die();
        }
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
                        }
                    }
                }
            }
            if ($filtr != null)
                $filtr .= " or ";
            if (isset($src_tcp_port))
                $filtr .= "(ip.addr==".$src_ip." and ip.addr==".$dst_ip." and tcp.port==".$src_tcp_port." and tcp.port==".$dst_tcp_port.")";
            else if (isset($src_udp_port))
                $filtr .= "(ip.addr==".$src_ip." and ip.addr==".$dst_ip." and udp.port==".$src_udp_port." and udp.port==".$dst_udp_port.")";
            else
                $filtr .= "(ip.addr==".$src_ip." and ip.addr==".$dst_ip.")";
            unset($src_tcp_port);
            unset($src_udp_port);
        }
        
        $cmd = "tshark -r ".$pcap_file." -R \"".$filtr."\" -w ".$out_pcap;
        system($cmd);
    }
}
?>
