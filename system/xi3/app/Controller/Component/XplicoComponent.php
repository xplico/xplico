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

include_once APP . 'Config' . DS . 'database.php';

class XplicoComponent extends Component
{
    var $Session;

    function startup(Controller $controller) {
        // This method takes a reference to the controller which is loading it.
        // Perform controller initialization here.
        $this->Session = $controller->Session;
    }
    
    function leftmenuarray($open) {
        $solid = $this->Session->read('sol');
        $menu_left = array('active' => $open, 'sections' => array(
                               array('name' => __('Case'), 'sub' => array(
                                         array('name' => __('Cases'), 'link' => '/pols'),
                                         array('name' => __('Sessions'), 'link' => '/sols/index'),
                                         array('name' => __('Session'), 'link' => '/sols/view/'.$solid)
                                         )
                                   ),
                               array('name' => __('Graphs'), 'sub' => array(
                                         array('name' => __('Dns'), 'link' => '/dns_messages/index'),
                                         array('name' => __('Arp'), 'link' => '/arps/index'),
                                         array('name' => __('Icmpv6'), 'link' => '/icmpv6s/index'),
                                         array('name' => __('GeoMap'), 'link' => '/inputs/geomap')
                                         )
                                   ),
                               array('name' => __('Web'), 'sub' => array(
                                         array('name' => __('Site'), 'link' => '/webs/index'),
                                         array('name' => __('Feed'), 'link' => '/feeds/index'),
                                         array('name' => __('Images'), 'link' => '/webs/images')
                                         )
                                   ),
                               array('name' => __('Mail'), 'sub' => array(
                                         array('name' => __('Email'), 'link' => '/emails/index'),
                                         array('name' => __('Webmail'), 'link' => '/webmails/index')
                                         )
                                   ),
                               array('name' => __('Voip'), 'sub' => array(
                                         array('name' => __('Sip'), 'link' => '/sips/index'),
                                         array('name' => __('Mgcp'), 'link' => '/mgcps/index'),
                                         array('name' => __('Rtp'), 'link' => '/rtps/index')
                                         )
                                   ),
                               array('name' => __('Share'), 'sub' => array(
                                         array('name' => __('HttpFile'), 'link' => '/httpfiles/index'),
                                         array('name' => __('Ftp'), 'link' => '/ftps/index'),
                                         array('name' => __('Tftp'), 'link' => '/tftps/index'),
                                         array('name' => __('Printer'), 'link' => '/pjls/index'),
                                         array('name' => __('Mms'), 'link' => '/mms/index')
                                         )
                                   ),
                               array('name' => __('Chat'), 'sub' => array(
                                         array('name' => __('Nntp'), 'link' => '/nntp_groups/index'),
                                         array('name' => __('Facebook'), 'link' => '/fbuchats/index'),
                                         array('name' => __('MSN'), 'link' => '/msn_chats/index'),
                                         array('name' => __('Yahoo MSG'), 'link' => '/webymsgs/index'),
                                         array('name' => __('WhatsApp'), 'link' => '/whatsapps/index'),
                                         array('name' => __('IRC'), 'link' => '/ircs/index'),
                                         array('name' => __('Paltalk'), 'link' => '/paltalk_rooms/index'),
                                         array('name' => __('Paltalk Exp'), 'link' => '/paltalk_exps/index')
                                         )
                                   ),
                               array('name' => __('Shell'), 'sub' => array(
                                         array('name' => __('Telnet'), 'link' => '/telnets/index'),
                                         array('name' => __('Syslog'), 'link' => '/syslogs/index')
                                         )
                                   ),
                               array('name' => __('Undecoded'), 'sub' => array(
                                         array('name' => __('TCP-UDP'), 'link' => '/unknows/index'),
                                         array('name' => __('Dig'), 'link' => '/unkfiles/index')
                                         )
                                   )
                               )
            );
        return $menu_left;        
    }

    function adminleftmenu() {
        $menu_left = array('active' => '0', 'sections' => array(
                               array('name' => __('Menu'), 'sub' => array(
                                         array('name' => __('Config'), 'link' => '/configurations'),
                                         array('name' => __('Dissectors'), 'link' => '/configurations/dissectors'),
                                         array('name' => __('Groups'), 'link' => '/admins/groups'),
                                         array('name' => __('Users'), 'link' => '/admins/users'),
                                         array('name' => __('New group'), 'link' => '/admins/gadd'),
                                         array('name' => __('New user'), 'link' => '/admins/uadd'),
                                         array('name' => __('Cases'), 'link' => '/pols'),
                                         )
                                   )
                               )
            );
        return $menu_left;
    }

    function checkXplicoStatus(){
        //Check for Xplico process status ("dema"). 0=not running; 1=running.
        $isXplicoRunning = 0;
        
        if (file_exists('/var/run/dema.pid')) {
            $foca = fopen('/var/run/dema.pid', 'r');
            if ($foca) {
                $dema_pid = fgets($foca, 200);
                fclose($foca);
                $dema_pid = str_replace(array("\r\n", "\n", "\r"), ' ', $dema_pid);
                $foca = popen('ps -p '.$dema_pid.' | grep dema', 'r');
                if ($foca) {
                    while (!feof($foca)) {
                        $dema_pid = fgets($foca, 200);
                        if (strstr($dema_pid, 'dema'))
                            $isXplicoRunning = 1;
                    }
                    pclose($foca);
                }
            }
        }
        return $isXplicoRunning;
    }


    function startStopXplico($futureStatus){
        system("sudo killall -9 /opt/xplico/bin/dema > /dev/null 2>&1 &");
        if ($futureStatus == 1) {
            system ("sudo /opt/xplico/script/sqlite_demo.sh > /dev/null 2>&1 &");
        }
        sleep (1);      //Necessary, calling the OS needs some time...
        return $this->checkXplicoStatus();
    }

    //Yes, i know, this execs on php will send me to Hell.
    function getDemaVersion() {
        return exec('/opt/xplico/bin/dema -v  |  cut -b 6,7,8,9,10');
    }

    function getXplicoVersion() {
        return exec('/opt/xplico/bin/xplico -v  |  cut -b 8,9,10,11,12');
    }

    function getSqliteVersion() {
        return exec('sqlite3 -version | cut -c 1-6');
    }

    function getCakephpVersion() {
        return Configure::version();
    }
    function getApacheVersion() {
        return apache_get_version();
    }

    function getPHPVersion() {
        $ver = exec('php -v | grep PHP | grep built | cut -b 5,6,7,8,9 ');
        if (empty($ver))
            $ver = exec('php -v | grep PHP | head -1 | cut -b 5,6,7,8,9 ');
        return $ver;
    }

    function gettcpdumpVersion() {
        return exec('tcpdump -V 2>&1 | grep tcpdump | grep version | cut -b 17,18,19,20,21');
    }
    
    function getTsharkVersion() {
        return exec('tshark -v | grep TShark |  cut -c 20-26');
    }

    function getlameVersion() {
        $ver = exec('lame -V 2>&1 | grep version | cut -b 21,22,23,24,25,26,27');
        if (empty($ver))
            $ver = exec('lame -V 2>&1 | grep version | cut -b 21,22,23,24,25,26,27');
        return $ver;
    }

    function getGNULinuxVersion() {
        $GNU_L_V=exec('lsb_release -i | cut -b 17,18,19,20,21,21,22,23,24,25,26');
        if (!empty($GNU_L_V)) {
            $GNU_L_V=$GNU_L_V.exec('lsb_release -r | cut -b 9,10,11,12,13,14,15,16,17');
            $GNU_L_V=$GNU_L_V.exec('lsb_release -c | cut -b 10,11,12,13,14,15,16,17');
        }
        else {
            $GNU_L_V=exec('uname -r');
        }
    	return $GNU_L_V;
    }
    
    function getKernelVersion() {
        return exec('uname -r | cut -c 1-6');
    }

    function getLibPCAPVersion() {
        return exec ('tcpdump -V 2>&1  | grep libpcap | grep version | cut -b 17,18,19,20,21');
    }

    function getxplicoAlertsVersion() {
        if (file_exists('/opt/xplico/bin/xplicoAlerts')) {
            //return exec ('tcpdump -V 2> /tmp/output.libpcap.txt ; cat /tmp/output.libpcap.txt  | grep libpcap | grep version | cut -b 17,18,19,20,21 ; rm output.libpcap.txt ');      
        }
        else {
            return __("Not installed");
        }
    }

    function getRecodeVersion() {
        return exec ('recode --version  |  grep "recode" | cut -b 13,14,15,16 ');
    }

    function getPythonVersion() {
        return exec ('python3 --version 2> /tmp/output.python.version.txt ; cat /tmp/output.python.version.txt | cut -b 8,9,10,11,12,13; rm /tmp/output.python.version.txt;');
    }

    function getSoxVersion() {
        return exec ('sox --version  | cut -c 16-21');
    }

    function getVideosnarfVersion() {
        if (file_exists('/usr/bin/videosnarf')) {
            return exec ('videosnarf | grep Starting | cut -b 20,21,22,23,24,25,26,27');
        }
        else if (file_exists('/opt/xplico/bin/videosnarf')) {
            return exec ('/opt/xplico/bin/videosnarf | grep Starting | cut -b 20,21,22,23,24,25,26,27');
        }
        else {
            return __("Not installed");  //Suggestion: put here a link of a 'how-to install it'
        }
    }

    function isChecksumValidationActivated() {
        $cfg = file('/opt/xplico/cfg/xplico_install_lite.cfg');
        foreach ($cfg as $line) {
            if (strstr($line, '#MODULE') == FALSE) {
                if (strstr($line, 'MODULE=')) {
                    if (strstr($line, "_nocheck.so")) {
                        return FALSE;
                    }
                }
            }
        }
        return TRUE;
    }
    
    function isLastdataActivated() {
        $cfg = file('/opt/xplico/cfg/xplico_install_lite.cfg');
        foreach ($cfg as $line) {
            if (strstr($line, '#DISPATCH=') == FALSE) {
                if (strstr($line, 'DISPATCH=')) {
                    if (strstr($line, "_list.so")) {
                        return TRUE;
                    }
                }
            }
        }
        return FALSE;
    }
    
    function GhostPDLVersion() {
       if (file_exists('/usr/bin/pcl6')) {
            return exec ('pcl6 2>&1 | grep Version | cut -b 10,11,12,13');
       }
       else if (file_exists('/opt/xplico/bin/pcl6')) {
            return exec ('/opt/xplico/bin/pcl6 2>&1 | grep Version | cut -b 10,11,12,13');
       }
       else {
           return __("Not installed");  //Suggestion: put here a link of a 'how-to install it'
       }
    }
    
    function GeoIPVersion() {
        return exec('pkg-config --modversion geoip');
    }
    
    function getmaxSizePCAP() {
        //Max size able to upload at Apache. Look for parameters post_max_size and upload_max_filesize, and choose the minimun one.
        if (file_exists('/etc/php5/apache2/php.ini')) {
            $apacheConfigData = parse_ini_file("/etc/php5/apache2/php.ini");
        }
        else if (file_exists('/etc/php/php.ini')) {
            $apacheConfigData = parse_ini_file("/etc/php/php.ini");
        }
        else if (file_exists('/etc/php/7.0/apache2/php.ini')) {
            $apacheConfigData = parse_ini_file("/etc/php/7.0/apache2/php.ini");
        }
        
        return (min(intval($apacheConfigData['post_max_size']), intval($apacheConfigData['upload_max_filesize']))); 
    }

    function dbstorage() {
        $fields = get_class_vars('DATABASE_CONFIG');
        if ($fields['default']['datasource'] == 'Database/mysql')
            return 'MySQL';
        if ($fields['default']['datasource'] == 'Database/Sqlite')
            return 'SQLite3';
        if ($fields['default']['datasource'] == 'Database/postgres')
            return 'PostgreSQL';
        return $fields['default']['datasource'];
    }
    
    function dbissqlite() {
        $fields = get_class_vars('DATABASE_CONFIG');
        if ($fields['default']['datasource'] == 'Database/Sqlite')
            return TRUE;
        return FALSE;
    }

    function existsXplicoNewVersion() {
        $handle = fopen('http://projects.xplico.org/version/xplico_ver.txt', 'r');
        if ($handle == FALSE) {
            return __("Error connecting to Internet");
        }
        
        $lastVersion = fread($handle, 50);
        $lastVersion = str_replace('version=', '', $lastVersion);
        $lastVersion = str_replace("\n", '', $lastVersion);
        $lastVersion = str_replace("\r", '', $lastVersion);
        $installedVersion = $this->getXplicoVersion();
        if ($lastVersion > $installedVersion) {
            return __('There is a new version of Xplico: ').$lastVersion;
        }
        else {
            return __('There is not a new version of Xplico');
        }
    }
    
    function Geopoint() {
        $cfg = file('/opt/xplico/cfg/xplico_install_lite.cfg');
        $geo = array();
        foreach ($cfg as $line) {
            if (strstr($line, 'DISPATCH_GEPMAP_LAT=') != FALSE) {
                $geo['latitude'] = str_replace( 'DISPATCH_GEPMAP_LAT=', '', $line);
            }
            else if (strstr($line, 'DISPATCH_GEPMAP_LONG=') != FALSE) {
                $geo['longitude'] = str_replace( 'DISPATCH_GEPMAP_LONG=', '', $line);
            }
        }
        return $geo;
    }
}
?>
