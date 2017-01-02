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
  /*
   * Uses MIME E-mail message parser classes written by Manuel Lemos:  http://www.phpclasses.org/browse/package/3169.html
   */

require_once 'rfc822_addresses.php';
require_once 'mime_parser.php';

App::uses('Sanitize', 'Utility');


function TmpDir() {
        $base = sys_get_temp_dir();
        if( substr( $base, -1 ) != '/' )
              $base .= '/';
        do {
              $path = $base.'mime-'.mt_rand();
        } while( !mkdir( $path, 0700 ) );
      
        return $path;
}

function AddressList($arr) {
        if (!isset($arr))
            return null;
        $list = null;
        foreach($arr as $data) {
            if ($list != null)
                $list = $list.", ";
            if (isset($data['name']))
                $list = $list." ".$data['name'];
            if (isset($data['address']))
                $list = $list." <".$data['address'].">";
        }
    
        return $list;
}

class WebmailsController extends AppController {

        var $name = 'Webmails';
        var $helpers = array('Html', 'Form');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Webmail.capture_date' => 'desc'));

        function beforeFilter() {
                $groupid = $this->Session->read('group');
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                if (!$groupid || !$polid || !$solid) {
                    $this->redirect('/users/login');
                }
        }
        
        function yahoo() {
            if ($this->Session->check('service')) {
                $serv = $this->Session->read('service');
                if ($serv != 'yahoo')
                    $this->Session->delete('srch_wm');
            }
            $this->Session->write('service', 'yahoo');
            $this->redirect('/webmails/index');
            die();
        }

        function aol() {
            if ($this->Session->check('service')) {
                $serv = $this->Session->read('service');
                if ($serv != 'aol')
                    $this->Session->delete('srch_wm');
            }
            $this->Session->write('service', 'aol');
            $this->redirect('/webmails/index');
            die();
        }
        
        function live() {
            if ($this->Session->check('service')) {
                $serv = $this->Session->read('service');
                if ($serv != 'live')
                    $this->Session->delete('srch_wm');
            }
            $this->Session->write('service', 'live');
            $this->redirect('/webmails/index');
            die();
        }
        
        function libero() {
            if ($this->Session->check('service')) {
                $serv = $this->Session->read('service');
                if ($serv != 'libero')
                    $this->Session->delete('srch_wm');
            }
            $this->Session->write('service', 'libero');
            $this->redirect('/webmails/index');
            die();
        }

        function index($id = null) {
            if ($this->Session->check('service')) {
                $service = $this->Session->read('service');
                $filter['Webmail.service'] = $service;
            }
            $solid = $this->Session->read('sol');
            $this->Webmail->recursive = -1;
            
            $filter = array('Webmail.sol_id' => $solid);
            // host selezionato
            $host_id = $this->Session->read('host_id');
            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Webmail.source_id'] = $host_id["host"];
            }
            $srch = null;
            if ($this->Session->check('srch_wm')) {
                $srch = $this->Session->read('srch_wm');
            }
            if (!empty($this->request->data)) {
                $srch = $this->request->data['Webmails']['search'];
            }
            if (!empty($srch)) {
                $filter['OR'] = array();
                $filter['OR']['Webmail.subject LIKE'] = "%$srch%";
                $filter['OR']['Webmail.sender LIKE'] = "%$srch%";
                $filter['OR']['Webmail.receivers LIKE'] = "%$srch%";
            }
            $msgs = $this->paginate('Webmail', $filter);
            $this->Session->write('srch_wm', $srch);
            $this->set('emails', $msgs);
            $this->set('srchd', $srch);
            $this->set('menu_left', $this->Xplico->leftmenuarray(3) );
	}

	function view($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->set('menu_left', $this->Xplico->leftmenuarray(3) );
                $this->Webmail->recursive = -1;
                $email = $this->Webmail->read(null, $id);
                if ($polid != $email['Webmail']['pol_id'] || $solid != $email['Webmail']['sol_id']) {
                    $this->redirect('/users/login');
                }
                $this->Session->write('emailid', $id);
                $this->set('email', $email);
                
                /* destroy last tmp dir */
                $tmp_dir = $this->Session->read('mimedir');
                system('rm -rf '.$tmp_dir);
                /* create dir to put decoded data */
                $tmp_dir = TmpDir();
                $this->Session->write('mimedir', $tmp_dir);

                /* decode mime */
                $mime_parser = new mime_parser_class;
                $mime_parser->mbox = 0; // single message file
                $mime_parser->decode_bodies = 1; // decde bodies
                $mime_parser->ignore_syntax_errors = 1;
                $mime_parser->extract_addresses = 0;
                $parse_parameters = array(
                    'File' => $email['Webmail']['mime_path'],
                    'SaveBody' => $tmp_dir, // save the message body parts to a directory
                    'SkipBody' => 1, // Do not retrieve or save message body parts
                    );
                
                if (!$mime_parser->Decode($parse_parameters, $mime_decoded)) {
                    
                }
                elseif ($mime_parser->Analyze($mime_decoded[0], $mime_parsed)) {
                    /* add 'to' and 'from' string */
                    if (isset($mime_parsed['To']))
                        $mime_parsed['to'] = AddressList($mime_parsed['To']);
                    else
                        $mime_parsed['to'] = '---';
                    if (isset($mime_parsed['From']))
                        $mime_parsed['from'] = AddressList($mime_parsed['From']);
                    else
                        $mime_parsed['from'] = '---';
                    $this->set('mailObj', $mime_parsed);
                    //print_r($mime_parsed);

                    // register visualization
                    if (!$email['Webmail']['first_visualization_user_id']) {
                        $uid = $this->Session->read('userid');
                        $email['Webmail']['first_visualization_user_id'] = $uid;
                        $email['Webmail']['viewed_date'] = date("Y-m-d H:i:s");
                        $this->Webmail->save($email);
                    }
                }
        }

        function eml() {
            $id = $this->Session->read('emailid');
            if (!$id) {
                $this->redirect('/users/login');
            }
            else {
                $this->Webmail->recursive = -1;
                $email = $this->Webmail->read(null, $id);
                $this->autoRender = false;
                header("Content-Disposition: attachment; filename=mail".$id.".eml");
                header("Content-Type: message/rfc822");
                header("Content-Length: " . filesize($email['Webmail']['mime_path']));
                readfile($email['Webmail']['mime_path']);
                exit();
            }
        }

        function info() {
            $id = $this->Session->read('emailid');
            if (!$id) {
                $this->redirect('/users/login');
            }
            else {
                $this->Webmail->recursive = -1;
                $email = $this->Webmail->read(null, $id);
                $this->autoRender = false;
                header("Content-Disposition: filename=info".$id.".xml");
                header("Content-Type: application/xhtml+xml; charset=utf-8");
                header("Content-Length: " . filesize($email['Webmail']['flow_info']));
                readfile($email['Webmail']['flow_info']);
                exit();
            }
        }

        function content($path=null) {
            $tmp_dir = $this->Session->read('mimedir');
            if (!$path || !$tmp_dir) {
                exit();
            }
            $this->autoRender = false;
            header("Content-Type: binary");
            if (file_exists($tmp_dir."/".$path))
                readfile($tmp_dir."/".$path);
            exit();
        }

        function pcap() {
            $id = $this->Session->read('emailid');
            if (!$id) {
                $this->redirect('/users/login');
            }
            else {
                $this->Webmail->recursive = -1;
                $email = $this->Webmail->read(null, $id);
                $file_pcap = "/tmp/email_".time()."_".$id.".pcap";
                $this->Xml2Pcap->doPcap($file_pcap, $email['Webmail']['flow_info']);
                $this->autoRender = false;
                header("Content-Disposition: filename=webmail_".$id.".pcap");
                header("Content-Type: binary");
                header("Content-Length: " . filesize($file_pcap));
                @readfile($file_pcap);
                unlink($file_pcap);
                exit();
            }
        }
}
?>
