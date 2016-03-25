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

class XplicoComponent extends Object
{
    var $controller = true;
    var $Session;

    function startup(&$controller) {
        // This method takes a reference to the controller which is loading it.
        // Perform controller initialization here.
        $this->Session = $controller->Session;
    }
    
    function leftmenuarray($open) {
        $solid = $this->Session->read('sol');
        $menu_left = array('active' => $open, 'sections' => array(
                               array('name' => __('Case', true), 'sub' => array(
                                         array('name' => __('Cases', true), 'link' => '/pols'),
                                         array('name' => __('Sessions', true), 'link' => '/sols/index'),
                                         array('name' => __('Session', true), 'link' => '/sols/view/'.$solid)
                                         )
                                   ),
                               array('name' => __('Graphs', true), 'sub' => array(
                                         array('name' => __('Dns', true), 'link' => '/dns_messages/index'),
                                         array('name' => __('Arp', true), 'link' => '/arps/index'),
                                         array('name' => __('Icmpv6', true), 'link' => '/icmpv6s/index'),
                                         array('name' => __('GeoMap', true), 'link' => '/inputs/geomap')
                                         )
                                   ),
                               array('name' => __('Web', true), 'sub' => array(
                                         array('name' => __('Site', true), 'link' => '/webs/index'),
                                         array('name' => __('Feed', true), 'link' => '/feeds/index'),
                                         array('name' => __('Images', true), 'link' => '/webs/images')
                                         )
                                   ),
                               array('name' => __('Mail', true), 'sub' => array(
                                         array('name' => __('Email', true), 'link' => '/emails/index'),
                                         array('name' => __('Webmail', true), 'link' => '/webmails/index')
                                         )
                                   ),
                               array('name' => __('Voip', true), 'sub' => array(
                                         array('name' => __('Sip', true), 'link' => '/sips/index'),
                                         array('name' => __('Mgcp', true), 'link' => '/mgcps/index'),
                                         array('name' => __('Rtp', true), 'link' => '/rtps/index')
                                         )
                                   ),
                               array('name' => __('Share', true), 'sub' => array(
                                         array('name' => __('HttpFile', true), 'link' => '/httpfiles/index'),
                                         array('name' => __('Ftp', true), 'link' => '/ftps/index'),
                                         array('name' => __('Tftp', true), 'link' => '/tftps/index'),
                                         array('name' => __('Printer', true), 'link' => '/pjls/index'),
                                         array('name' => __('Mms', true), 'link' => '/mms/index')
                                         )
                                   ),
                               array('name' => __('Chat', true), 'sub' => array(
                                         array('name' => __('Nntp', true), 'link' => '/nntp_groups/index'),
                                         array('name' => __('Facebook', true), 'link' => '/fbuchats/index'),
                                         array('name' => __('MSN', true), 'link' => '/msn_chats/index'),
                                         array('name' => __('Yahoo MSG', true), 'link' => '/webymsgs/index'),
                                         array('name' => __('WhatsApp', true), 'link' => '/whatsapps/index'),
                                         array('name' => __('IRC', true), 'link' => '/ircs/index'),
                                         array('name' => __('Paltalk', true), 'link' => '/paltalk_rooms/index'),
                                         array('name' => __('Paltalk Exp', true), 'link' => '/paltalk_exps/index')
                                         )
                                   ),
                               array('name' => __('Shell', true), 'sub' => array(
                                         array('name' => __('Telnet', true), 'link' => '/telnets/index'),
                                         array('name' => __('Syslog', true), 'link' => '/syslogs/index')
                                         )
                                   ),
                               array('name' => __('Undecoded', true), 'sub' => array(
                                         array('name' => __('TCP-UDP', true), 'link' => '/unknows/index'),
                                         array('name' => __('Dig', true), 'link' => '/unkfiles/index')
                                         )
                                   )
                               )
            );
        return $menu_left;        
    }

    function adminleftmenu() {
        $menu_left = array('active' => '0', 'sections' => array(
                               array('name' => __('Menu', true), 'sub' => array(
                                         array('name' => __('Config', true), 'link' => '/configurations'),
                                         array('name' => __('Dissectors', true), 'link' => '/configurations/dissectors'),
                                         array('name' => __('Groups', true), 'link' => '/admins/groups'),
                                         array('name' => __('Users', true), 'link' => '/admins/users'),
                                         array('name' => __('New group', true), 'link' => '/admins/gadd'),
                                         array('name' => __('New user', true), 'link' => '/admins/uadd'),
                                         array('name' => __('Cases', true), 'link' => '/pols'),
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
            $ver = exec('php -v | grep PHP | grep built | cut -b 5,6,7,8,9 ');
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
	return exec('uname -r | cut -c 1-6');	}

    function getLibPCAPVersion() {
	return exec ('tcpdump -V 2>&1  | grep libpcap | grep version | cut -b 17,18,19,20,21');   	}

    function getxplicoAlertsVersion() {
	if (file_exists('/opt/xplico/bin/xplicoAlerts')) {
		//return exec ('tcpdump -V 2> /tmp/output.libpcap.txt ; cat /tmp/output.libpcap.txt  | grep libpcap | grep version | cut -b 17,18,19,20,21 ; rm output.libpcap.txt ');   	
		}
	else
		{return __("Not installed", true);} 
	}

    function getRecodeVersion() {
        return exec ('recode --version  |  grep "recode" | cut -b 13,14,15,16 ');
    }

    function getPythonVersion() {
        return exec ('python3 --version 2> /tmp/output.python.version.txt ; cat /tmp/output.python.version.txt | cut -b 8,9,10,11,12,13; rm /tmp/output.python.version.txt;');
    }

    function getSoxVersion() {
        return exec ('sox --version  | cut --c 16-21');
    }

    function getVideosnarfVersion() {
	if (file_exists('/usr/bin/videosnarf')) {
        	return exec ('videosnarf | grep Starting | cut -b 20,21,22,23,24,25,26,27'); }
        else {
	        return __("Not installed", true); }  //Suggestion: put here a link of a 'how-to install it'
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
            return exec ('pcl6 2>&1 | grep Version | cut -b 10,11,12,13'); }
       else {
           return __("Not installed", true); }  //Suggestion: put here a link of a 'how-to install it'
    }
    
    function GeoIPVersion() {
        return exec('pkg-config --modversion geoip');
    }
    
    function getmaxSizePCAP() {
        //Max size able to upload at Apache. Look for parameters post_max_size and upload_max_filesize, and choose the minimun one.
        if (file_exists('/etc/php5/apache2/php.ini')) {
	        $apacheConfigData = parse_ini_file("/etc/php5/apache2/php.ini");
		}
		else {
			$apacheConfigData = parse_ini_file("/etc/php/php.ini");
		}
        return (min(intval($apacheConfigData[      'post_max_size']), intval($apacheConfigData['upload_max_filesize'])));	
    }

    function dbstorage() {
        $fields = get_class_vars('DATABASE_CONFIG');
        if ($fields['default']['driver'] == 'mysql')
            return 'MySQL';
        if ($fields['default']['driver'] == 'sqlite3')
            return 'SQLite 3';
        if ($fields['default']['driver'] == 'postgres')
            return 'PostgreSQL';
        return $fields['default']['driver'];
    }

    function existsXplicoNewVersion() {
	$handle = fopen('http://projects.xplico.org/version/xplico_ver.txt', 'r');
	if ($handle == FALSE) {
            return __("Error connecting to Internet", true);}	
        
	$lastVersion = fread($handle, 50);
        $lastVersion = str_replace('version=', '', $lastVersion);
        $lastVersion = str_replace("\n", '', $lastVersion);
        $lastVersion = str_replace("\r", '', $lastVersion);
	$installedVersion = $this->getXplicoVersion();
	if ($lastVersion > $installedVersion) {
            return __('There is a new version of Xplico: ', true).$lastVersion;
        }
        else {
            return __('There is not a new version of Xplico', true);
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
