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
   * Carlos Gacimartín <cgacimartin@gmail.com>
   * Portions created by the Initial Developer are Copyright (C) 2010
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

App::uses('Sanitize', 'Utility');

class ConfigurationsController extends AppController
{
	//Meter en los paquetes a instalar el phpsysinfo ?

    //Revisar estas librerías, seguramente no las necesite todas.
    var $helpers = array('Html', 'Form');
    var $components = array('RequestHandler', 'Security', 'Xplico');
    var $uses = array('Param', 'User');
    

    function beforeFilter() {
        if (!$this->Session->check('admin')) {
            $this->redirect('/users/login');
        }
        $this->Session->delete('pol');
        $this->Session->delete('sol');
        $this->Security->blackHoleCallback='invalid';
        // admin left menu
        $this->set('menu_left', $this->Xplico->adminleftmenu());
    }

    function invalid() {
        header('HTTP/x 400 Bad Request');
        echo('<h1>HTTP: 400 Bad Request</h1>');
        echo('<p>We\'re sorry - there has been a problem processing your request.  Please try submitting the form again.</p>');
        die();
    }

    function index() {
	if (isset($this->request->data['Param']['startXplico']) ) {
            //A way to start/restart Xplico from the web interface (aka "xi")
            $this->Xplico->startStopXplico($this->request->data['Param']['startXplico']);
        }
        
        $this->set('isXplicoRunning', $this->Xplico->checkXplicoStatus() );
        $this->set('demaVersion',     $this->Xplico->getDemaVersion()    );
        $this->set('xplicoVersion',   $this->Xplico->getXplicoVersion()  );
        $this->set('sqliteVersion',   $this->Xplico->getSqliteVersion()  );
        $this->set('cakephpVersion',  $this->Xplico->getCakephpVersion()  );
        $this->set('tcpdumpVersion',  $this->Xplico->gettcpdumpVersion()  );
        $this->set('apacheVersion',   $this->Xplico->getApacheVersion()  );
        $this->set('PHPVersion', 	  $this->Xplico->getPHPVersion()  );
        $this->set('TsharkVersion',   $this->Xplico->getTsharkVersion()  );
        $this->set('lameVersion',     $this->Xplico->getlameVersion()  );
        $this->set('GNULinuxVersion', $this->Xplico->getGNULinuxVersion()  );
        $this->set('KernelVersion',   $this->Xplico->getKernelVersion()  );
        $this->set('LibPCAPVersion',  $this->Xplico->getLibPCAPVersion()  );
        $this->set('xplicoAlertsVersion',  $this->Xplico->getxplicoAlertsVersion()  );
        $this->set('RecodeVersion',  $this->Xplico->getRecodeVersion()  );
        $this->set('PythonVersion',  $this->Xplico->getPythonVersion()  );
        $this->set('SoxVersion',  	 $this->Xplico->getSoxVersion()  );
        $this->set('videosnarfVersion',  	 $this->Xplico->getVideosnarfVersion()  );
        $this->set('isChecksumValidationActivated', $this->Xplico->isChecksumValidationActivated() );
        $this->set('isLastdataActivated', $this->Xplico->isLastdataActivated() );
        $this->set('GeoIPVersion', 	  $this->Xplico->GeoIPVersion() );
        $this->set('GhostPDLVersion', $this->Xplico->GhostPDLVersion() );
        $this->set('maxSizePCAP', $this->Xplico->getmaxSizePCAP() );
        $this->set('dbstorage', $this->Xplico->dbstorage() );
        $geo = $this->Xplico->Geopoint();
        $this->set('lat', $geo['latitude']);
        $this->set('long', $geo['longitude']);
    }

    function checkupdates() {
        $this->Session->setflash($this->Xplico->existsXplicoNewVersion());
        $this->redirect('/configurations/index');
    }
    
    function geoposition() {
        if (!empty($this->request->data)) {
            if (is_numeric($this->request->data['GPSposition']['long']) == FALSE ||
                is_numeric($this->request->data['GPSposition']['lat']) == FALSE)
                $this->Session->setflash("Input error. Please insert only numbers!");
            $files = array('/opt/xplico/cfg/mfbc_install_lite.cfg', '/opt/xplico/cfg/mfile_cli.cfg',
                           '/opt/xplico/cfg/mfile_install_lite.cfg', '/opt/xplico/cfg/mpaltalk_cli.cfg',
                           '/opt/xplico/cfg/mpaltalk_install_lite.cfg', '/opt/xplico/cfg/mwmail_cli.cfg',
                           '/opt/xplico/cfg/mwmail_install_lite.cfg', '/opt/xplico/cfg/xplico_cli.cfg',
                           '/opt/xplico/cfg/xplico_cli_nc.cfg', '/opt/xplico/cfg/xplico_install_lite.cfg',
                           '/opt/xplico/cfg/mfbc_install_mysql.cfg',
                           '/opt/xplico/cfg/mfile_install_mysql.cfg',
                           '/opt/xplico/cfg/mpaltalk_install_mysql.cfg',
                           '/opt/xplico/cfg/mwmail_install_mysql.cfg',
                           '/opt/xplico/cfg/xplico_install_mysql.cfg',
                           '/opt/xplico/cfg/mfbc_install_postgres.cfg',
                           '/opt/xplico/cfg/mfile_install_postgres.cfg',
                           '/opt/xplico/cfg/mpaltalk_install_postgres.cfg',
                           '/opt/xplico/cfg/mwmail_install_postgres.cfg',
                           '/opt/xplico/cfg/xplico_install_postgres.cfg');
            foreach ($files as $cfg) {
                if (!file_exists($cfg))
                    continue;
                $cfg_tmp = '/opt/xplico/cfg/tmp.cfg';
                $cfgparams = file($cfg);
                $fh = fopen($cfg_tmp, 'w');
                foreach ($cfgparams as $line) {
                    if (strstr($line, 'DISPATCH_GEPMAP_LAT=') != FALSE) {
                        fwrite($fh, 'DISPATCH_GEPMAP_LAT='.$this->request->data['GPSposition']['lat']."\n");
                    }
                    else if (strstr($line, 'DISPATCH_GEPMAP_LONG=') != FALSE) {
                        fwrite($fh, 'DISPATCH_GEPMAP_LONG='.$this->request->data['GPSposition']['long']."\n");
                    }
                    else {
                        fwrite($fh, $line);
                    }
                }
                fclose($fh);
                rename($cfg_tmp, $cfg);
            }
        }
        $this->redirect('/configurations/index');
    }

    function lastdatatogle() {
        $files = array('/opt/xplico/cfg/mfbc_install_lite.cfg', '/opt/xplico/cfg/mfile_cli.cfg',
                       '/opt/xplico/cfg/mfile_install_lite.cfg', '/opt/xplico/cfg/mpaltalk_cli.cfg',
                       '/opt/xplico/cfg/mpaltalk_install_lite.cfg', '/opt/xplico/cfg/mwmail_cli.cfg',
                       '/opt/xplico/cfg/mwmail_install_lite.cfg', '/opt/xplico/cfg/xplico_cli.cfg',
                       '/opt/xplico/cfg/xplico_cli_nc.cfg', '/opt/xplico/cfg/xplico_install_lite.cfg',
                       '/opt/xplico/cfg/mfbc_install_mysql.cfg',
                       '/opt/xplico/cfg/mfile_install_mysql.cfg',
                       '/opt/xplico/cfg/mpaltalk_install_mysql.cfg',
                       '/opt/xplico/cfg/mwmail_install_mysql.cfg',
                       '/opt/xplico/cfg/xplico_install_mysql.cfg',
                       '/opt/xplico/cfg/mfbc_install_postgres.cfg',
                       '/opt/xplico/cfg/mfile_install_postgres.cfg',
                       '/opt/xplico/cfg/mpaltalk_install_postgres.cfg',
                       '/opt/xplico/cfg/mwmail_install_postgres.cfg',
                       '/opt/xplico/cfg/xplico_install_postgres.cfg');
        $disp = null;
        foreach ($files as $cfg) {
            if (!file_exists($cfg))
                continue;
            $cfg_tmp = '/opt/xplico/cfg/tmp.cfg';
            $cfgparams = file($cfg);
            $fh = fopen($cfg_tmp, 'w');
            foreach ($cfgparams as $line) {
                if (strstr($line, '#DISPATCH=') == FALSE) {
                    if (strstr($line, 'DISPATCH=')) {
                        if (!$disp) {
                            if (strstr($line, '_list.so')) {
                                $disp = 'disp_lite.so';
                                $disp_cli = 'disp_cli.so';
                                $disp_mysql = 'disp_ximysql.so';
                            }
                            else {
                                $disp = 'disp_lite_list.so';
                                $disp_cli = 'disp_cli_list.so';
                                $disp_mysql = 'disp_ximysql_list.so';
                            }
                        }
                        if (strstr($cfg, '_cli'))
                            fwrite($fh, 'DISPATCH='.$disp_cli."\n");
                        else if (strstr($cfg, '_mysql'))
                            fwrite($fh, 'DISPATCH='.$disp_mysql."\n");
                        else
                            fwrite($fh, 'DISPATCH='.$disp."\n");
                    }
                    else {
                        fwrite($fh, $line);
                    }
                }
            }
            fclose($fh);
            rename($cfg_tmp, $cfg);
        }
        $this->redirect('/configurations/index');
    }

    function checksumtogle() {
        $files = array('/opt/xplico/cfg/xplico_cli.cfg',
                       '/opt/xplico/cfg/xplico_install_lite.cfg',
                       '/opt/xplico/cfg/xplico_install_mysql.cfg',
                       '/opt/xplico/cfg/xplico_install_postgres.cfg');
        $checksum = null;
        foreach ($files as $cfg) {
            if (!file_exists($cfg))
                continue;
            $cfg_tmp = '/opt/xplico/cfg/tmp.cfg';
            $cfgparams = file($cfg);
            $fh = fopen($cfg_tmp, 'w');
            foreach ($cfgparams as $line) {
                if (strstr($line, '#MODULE')) {
                    $comment = '#';
                }
                else {
                    $comment = '';
                }
                if (strstr($line, 'MODULE=dis_icpmv6')) {
                    if (!$checksum) {
                        if (strstr($line, "_nocheck.so"))
                            $checksum =  '.so';
                        else
                            $checksum =  '_nocheck.so';
                    }
                    fwrite($fh, $comment.'MODULE=dis_icmpv6'.$checksum." LOG=FEWS\n");
                }
                else if (strstr($line, 'MODULE=dis_ip.') || strstr($line, 'MODULE=dis_ip_no')) {
                    if (!$checksum) {
                        if (strstr($line, "_nocheck.so"))
                            $checksum =  '.so';
                        else
                            $checksum =  '_nocheck.so';
                    }
                    fwrite($fh, $comment.'MODULE=dis_ip'.$checksum." LOG=FEWS\n");
                }
                else if (strstr($line, 'MODULE=dis_tcp.') || strstr($line, 'MODULE=dis_tcp_no')) {
                    if (!$checksum) {
                        if (strstr($line, "_nocheck.so"))
                            $checksum =  '.so';
                        else
                            $checksum =  '_nocheck.so';
                    }
                    fwrite($fh, $comment.'MODULE=dis_tcp'.$checksum." LOG=FEWS\n");
                }
                else if (strstr($line, 'MODULE=dis_tcp_soft') || strstr($line, 'MODULE=dis_tcp_soft_no')) {
                    if (!$checksum) {
                        if (strstr($line, "_nocheck.so"))
                            $checksum =  '.so';
                        else
                            $checksum =  '_nocheck.so';
                    }
                    fwrite($fh, $comment.'MODULE=dis_tcp_soft'.$checksum." LOG=FEWS\n");
                }
                else if (strstr($line, 'MODULE=dis_udp.') || strstr($line, 'MODULE=dis_udp_no')) {
                    if (!$checksum) {
                        if (strstr($line, "_nocheck.so"))
                            $checksum =  '.so';
                        else
                            $checksum =  '_nocheck.so';
                    }
                    fwrite($fh, $comment.'MODULE=dis_udp'.$checksum." LOG=FEWS\n");
                }
                else {
                    fwrite($fh, $line);
                }
            }
            fclose($fh);
            rename($cfg_tmp, $cfg);
        }
        $this->redirect('/configurations/index');
    }

    function dissectors($name = null) {
        if ($name != null) {
            $files = array('/opt/xplico/cfg/xplico_cli.cfg',
                           '/opt/xplico/cfg/xplico_install_lite.cfg',
                           '/opt/xplico/cfg/xplico_install_mysql.cfg',
                           '/opt/xplico/cfg/xplico_install_postgres.cfg');
            foreach ($files as $cfg) {
                if (!file_exists($cfg))
                    continue;
                $cfg_tmp = '/opt/xplico/cfg/tmp.cfg';
                $cfgparams = file($cfg);
                $fh = fopen($cfg_tmp, 'w');
                foreach ($cfgparams as $line) {
                    switch ($name) {
                    case 'pcapf':
                        if (strstr($line, 'dis_pcapf.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'pol':
                        if (strstr($line, 'dis_pol.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'eth':
                        if (strstr($line, 'dis_eth.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'pppoe':
                        if (strstr($line, 'dis_pppoe.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'ppp':
                        if (strstr($line, 'dis_ppp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'ipv6':
                        if (strstr($line, 'dis_ipv6.') || strstr($line, 'dis_ipv6_no')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'ip':
                        if (strstr($line, 'dis_ip.') || strstr($line, 'dis_ip_no')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'tcp':
                        if (strstr($line, 'dis_tcp_soft')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'udp':
                        if (strstr($line, 'dis_udp.') || strstr($line, 'dis_udp_no')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'http':
                        if (strstr($line, 'dis_http.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'pop':
                        if (strstr($line, 'dis_pop.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'imap':
                        if (strstr($line, 'dis_imap.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'smtp':
                        if (strstr($line, 'dis_smtp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'httpfd':
                        if (strstr($line, 'dis_httpfd.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'sip':
                        if (strstr($line, 'dis_sip.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'rtp':
                        if (strstr($line, 'dis_rtp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'rtcp':
                        if (strstr($line, 'dis_rtcp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'sdp':
                        if (strstr($line, 'dis_sdp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'l2tp':
                        if (strstr($line, 'dis_l2tp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'vlan':
                        if (strstr($line, 'dis_vlan.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'ftp':
                        if (strstr($line, 'dis_ftp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'dns':
                        if (strstr($line, 'dis_dns.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'icmp':
                        if (strstr($line, 'dis_icmp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'nntp':
                        if (strstr($line, 'dis_nntp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'irc':
                        if (strstr($line, 'dis_irc.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'ipp':
                        if (strstr($line, 'dis_ipp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'pjl':
                        if (strstr($line, 'dis_pjl.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'mms':
                        if (strstr($line, 'dis_mms.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'sll':
                        if (strstr($line, 'dis_sll.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'tftp':
                        if (strstr($line, 'dis_tftp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'ieee80211':
                        if (strstr($line, 'dis_ieee80211.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'llc':
                        if (strstr($line, 'dis_llc.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'fbwchat':
                        if (strstr($line, 'dis_fbwchat.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'telnet':
                        if (strstr($line, 'dis_telnet.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'webmail':
                        if (strstr($line, 'dis_webmail.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'msn':
                        if (strstr($line, 'dis_msn.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'paltalk':
                        if (strstr($line, 'dis_paltalk.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'arp':
                        if (strstr($line, 'dis_arp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'paltalk_exp':
                        if (strstr($line, 'dis_paltalk_exp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'radiotap':
                        if (strstr($line, 'dis_radiotap.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'tcp_grb':
                        if (strstr($line, 'dis_tcp_grb.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'udp_grb':
                        if (strstr($line, 'dis_udp_grb.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'ppi':
                        if (strstr($line, 'dis_ppi.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'syslog':
                        if (strstr($line, 'dis_syslog.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'prism':
                        if (strstr($line, 'dis_prism.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'null':
                        if (strstr($line, 'dis_null.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'chdlc':
                        if (strstr($line, 'dis_chdlc.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'webymsg':
                        if (strstr($line, 'dis_webymsg.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'mgcp':
                        if (strstr($line, 'dis_mgcp.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'whatsapp':
                        if (strstr($line, 'dis_wa.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;

                    case 'mpls':
                        if (strstr($line, 'dis_mpls.')) {
                            if (strstr($line, '#MODULE') == FALSE) {
                                $line = '#'.$line;
                            }
                            else {
                                $line = str_replace('#', '', $line);
                            }
                        }
                        break;
                    }
                    fwrite($fh, $line);
                }
                fclose($fh);
                rename($cfg_tmp, $cfg);
            }
        }
        $dissectors = array(
            'pcapf' => 'Off',
            'pol' => 'Off',
            'eth' => 'Off',
            'pppoe' => 'Off',
            'ppp' => 'Off',
            'ip' => 'Off',
            'ipv6' => 'Off',
            'tcp' => 'Off',
            'udp' => 'Off',
            'http' => 'Off',
            'pop' => 'Off',
            'imap' => 'Off',
            'smtp' => 'Off',
            'httpfd' => 'Off',
            'sip' => 'Off',
            'rtp' => 'Off',
            'rtcp' => 'Off',
            'sdp' => 'Off',
            'l2tp' => 'Off',
            'vlan' => 'Off',
            'ftp' => 'Off',
            'dns' => 'Off',
            'icmp' => 'Off',
            'nntp' => 'Off',
            'irc' => 'Off',
            'ipp' => 'Off',
            'pjl' => 'Off',
            'mms' => 'Off',
            'sll' => 'Off',
            'tftp' => 'Off',
            'ieee80211' => 'Off',
            'llc' => 'Off',
            'fbwchat' => 'Off',
            'telnet' => 'Off',
            'webmail' => 'Off',
            'msn' => 'Off',
            'paltalk' => 'Off',
            'arp' => 'Off',
            'paltalk_exp' => 'Off',
            'radiotap' => 'Off',
            'tcp_grb' => 'Off',
            'udp_grb' => 'Off',
            'ppi' => 'Off',
            'syslog' => 'Off',
            'prism' => 'Off',
            'null' => 'Off',
            'chdlc' => 'Off',
            'webymsg' => 'Off',
            'mgcp' => 'Off',
            'whatsapp' => 'Off',
            'mpls' => 'Off'
            );
        $cfg = file('/opt/xplico/cfg/xplico_install_lite.cfg');
        foreach ($cfg as $line) {
            if (strstr($line, '#MODULE') == FALSE) {
                if (strstr($line, 'MODULE=')) {
                    if (strstr($line, 'dis_pcapf.')) {
                        $dissectors['pcapf'] = 'On';
                    }
                    else if (strstr($line, 'dis_pol.')) {
                        $dissectors['pol'] = 'On';
                    }
                    else if (strstr($line, 'dis_eth.')) {
                        $dissectors['eth'] = 'On';
                    }
                    else if (strstr($line, 'dis_pppoe.')) {
                        $dissectors['pppoe'] = 'On';
                    }
                    else if (strstr($line, 'dis_ppp.')) {
                        $dissectors['ppp'] = 'On';
                    }
                    else if (strstr($line, 'dis_ipv6.') || strstr($line, 'dis_ipv6_no')) {
                        $dissectors['ipv6'] = 'On';
                    }
                    else if (strstr($line, 'dis_ip.') || strstr($line, 'dis_ip_no')) {
                        $dissectors['ip'] = 'On';
                    }
                    else if (strstr($line, 'dis_tcp_grb.')) {
                        $dissectors['tcp_grb'] = 'On';
                    }
                    else if (strstr($line, 'dis_udp_grb.')) {
                        $dissectors['udp_grb'] = 'On';
                    }
                    else if (strstr($line, 'dis_tcp_soft')) {
                        $dissectors['tcp'] = 'On';
                    }
                    else if (strstr($line, 'dis_udp.') || strstr($line, 'dis_udp_no')) {
                        $dissectors['udp'] = 'On';
                    }
                    else if (strstr($line, 'dis_http.')) {
                        $dissectors['http'] = 'On';
                    }
                    else if (strstr($line, 'dis_pop.')) {
                        $dissectors['pop'] = 'On';
                    }
                    else if (strstr($line, 'dis_imap.')) {
                        $dissectors['imap'] = 'On';
                    }
                    else if (strstr($line, 'dis_smtp.')) {
                        $dissectors['smtp'] = 'On';
                    }
                    else if (strstr($line, 'dis_httpfd.')) {
                        $dissectors['httpfd'] = 'On';
                    }
                    else if (strstr($line, 'dis_sip.')) {
                        $dissectors['sip'] = 'On';
                    }
                    else if (strstr($line, 'dis_rtp.')) {
                        $dissectors['rtp'] = 'On';
                    }
                    else if (strstr($line, 'dis_rtcp.')) {
                        $dissectors['rtcp'] = 'On';
                    }
                    else if (strstr($line, 'dis_sdp.')) {
                        $dissectors['sdp'] = 'On';
                    }
                    else if (strstr($line, 'dis_l2tp.')) {
                        $dissectors['l2tp'] = 'On';
                    }
                    else if (strstr($line, 'dis_vlan.')) {
                        $dissectors['vlan'] = 'On';
                    }
                    else if (strstr($line, 'dis_ftp.')) {
                        $dissectors['ftp'] = 'On';
                    }
                    else if (strstr($line, 'dis_dns.')) {
                        $dissectors['dns'] = 'On';
                    }
                    else if (strstr($line, 'dis_icmp.')) {
                        $dissectors['icmp'] = 'On';
                    }
                    else if (strstr($line, 'dis_nntp.')) {
                        $dissectors['nntp'] = 'On';
                    }
                    else if (strstr($line, 'dis_irc.')) {
                        $dissectors['irc'] = 'On';
                    }
                    else if (strstr($line, 'dis_ipp.')) {
                        $dissectors['ipp'] = 'On';
                    }
                    else if (strstr($line, 'dis_pjl.')) {
                        $dissectors['pjl'] = 'On';
                    }
                    else if (strstr($line, 'dis_mms.')) {
                        $dissectors['mms'] = 'On';
                    }
                    else if (strstr($line, 'dis_sll.')) {
                        $dissectors['sll'] = 'On';
                    }
                    else if (strstr($line, 'dis_tftp.')) {
                        $dissectors['tftp'] = 'On';
                    }
                    else if (strstr($line, 'dis_ieee80211.')) {
                        $dissectors['ieee80211'] = 'On';
                    }
                    else if (strstr($line, 'dis_llc.')) {
                        $dissectors['llc'] = 'On';
                    }
                    else if (strstr($line, 'dis_fbwchat.')) {
                        $dissectors['fbwchat'] = 'On';
                    }
                    else if (strstr($line, 'dis_telnet.')) {
                        $dissectors['telnet'] = 'On';
                    }
                    else if (strstr($line, 'dis_webmail.')) {
                        $dissectors['webmail'] = 'On';
                    }
                    else if (strstr($line, 'dis_msn.')) {
                        $dissectors['msn'] = 'On';
                    }
                    else if (strstr($line, 'dis_paltalk.')) {
                        $dissectors['paltalk'] = 'On';
                    }
                    else if (strstr($line, 'dis_arp.')) {
                        $dissectors['arp'] = 'On';
                    }
                    else if (strstr($line, 'dis_paltalk_exp.')) {
                        $dissectors['paltalk_exp'] = 'On';
                    }
                    else if (strstr($line, 'dis_radiotap.')) {
                        $dissectors['radiotap'] = 'On';
                    }
                    else if (strstr($line, 'dis_ppi.')) {
                        $dissectors['ppi'] = 'On';
                    }
                    else if (strstr($line, 'dis_syslog.')) {
                        $dissectors['syslog'] = 'On';
                    }
                    else if (strstr($line, 'dis_prism.')) {
                        $dissectors['prism'] = 'On';
                    }
                    else if (strstr($line, 'dis_null.')) {
                        $dissectors['null'] = 'On';
                    }
                    else if (strstr($line, 'dis_chdlc.')) {
                        $dissectors['chdlc'] = 'On';
                    }
                    else if (strstr($line, 'dis_webymsg.')) {
                        $dissectors['webymsg'] = 'On';
                    }
                    else if (strstr($line, 'dis_mgcp.')) {
                        $dissectors['mgcp'] = 'On';
                    }
                    else if (strstr($line, 'dis_wa.')) {
                        $dissectors['whatsapp'] = 'On';
                    }
                    else if (strstr($line, 'dis_mpls.')) {
                        $dissectors['mgcp'] = 'On';
                    }
                }
            }
        }
        $this->set('dissectors', $dissectors);
    }
}
?>
