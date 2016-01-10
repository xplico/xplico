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
  /*
   * Uses MIME E-mail message parser classes written by Manuel Lemos:  http://www.phpclasses.org/browse/package/3169.html
   */
uses('sanitize');
require_once 'rfc822_addresses.php';
require_once 'mime_parser.php';

function TmpDir() {
        $base = sys_get_temp_dir();
        if( substr( $base, -1 ) != '/' )
              $base .= '/';
        do {
              $path = $base.'mime-'.mt_rand();
        } while( !mkdir( $path, 0700 ) );
      
        return $path;
}
// *****************************************************************************************************
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

// *****************************************************************************************************
class EmailsController extends AppController {
        var $name = 'Emails';
        var $helpers = array('Html', 'Form', 'Javascript');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Email.capture_date' => 'desc'));

// *****************************************************************************************************
        function beforeFilter() {
                $groupid = $this->Session->read('group');
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                if (!$groupid || !$polid || !$solid) {
                    $this->redirect('/users/login');
                }
        }
// *****************************************************************************************************
        function index($id = null) {
            $solid = $this->Session->read('sol');
            $this->Email->recursive = -1;
            $filter = array(
			'Email.sol_id'		=> $solid      
//	  		'Email.relevance >'  	=> '3'
		);
            // host selezionato
            $host_id = $this->Session->read('host_id');
            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Email.source_id'] = $host_id["host"];
            }
            $srch = null;
            if ($this->Session->check('srch_email')) {
                $srch = $this->Session->read('srch_email');
            }
            if (!empty($this->data)) {
                $srch = $this->data['Emails']['search'];
            }

	    if (empty($this->data['Emails']['relevance'])) 
			{$filter['Email.relevance >'] =  0;}
		  else 
			{$filter['Email.relevance >'] = $this->data['Emails']['relevance'];}


            if (!empty($srch)) {
                $filter['OR']  = array();
                $filter['OR']['Email.subject 	LIKE'] =  "%$srch%";
                $filter['OR']['Email.sender 	LIKE'] =  "%$srch%";
                $filter['OR']['Email.receivers 	LIKE'] =  "%$srch%";
            }
            
            $msgs = $this->paginate('Email', $filter);
            $this->Session->write('srch_email', $srch);
            $this->set('emails', $msgs);
            $this->set('srchd',  $srch);
            $this->set('menu_left', $this->Xplico->leftmenuarray(3) );
    	    $this->set('relevanceoptions', array( '0'=>'0', '1'=>'1', '2'=>'2',  '3'=>'3', '4'=>'4', '5'=>'5', '100'=> __('Unknown', true)));
	}

// *****************************************************************************************************
        function edit($id = null) {
                if (!$id && empty($this->data)) {
                        $this->flash(__('Invalid Email', true), array('action' => 'index'));
                }
                if (!empty($this->data)) {
                        if ($this->Email->save($this->data)) {
                                $this->flash(__('The Email has been saved.', true), array('action' => 'index'));
                        } else {
                        }
                }
                if (empty($this->data)) {
                        $this->data = $this->Email->read(null, $id);
                }
        }	

// *****************************************************************************************************
	function view($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->set('menu_left', $this->Xplico->leftmenuarray(3) );
                $this->Email->recursive = -1;
                $email = $this->Email->read(null, $id);
                if ($polid != $email['Email']['pol_id'] || $solid != $email['Email']['sol_id']) {
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
                    'File' => $email['Email']['mime_path'],
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
                    //print_r($mime_parsed); die();

                    // register visualization
                    if (!$email['Email']['first_visualization_user_id']) {
                        $uid = $this->Session->read('userid');
                        $email['Email']['first_visualization_user_id'] = $uid;
                        $email['Email']['viewed_date'] = date("Y-m-d H:i:s");
                        $this->Email->save($email);
                    }
                }


           if (!$id && empty($this->data)) {
                        $this->flash(__('Invalid Email', true), array('action' => 'index'));
                }
                if (!empty($this->data)) {
                        if ($this->Email->save($this->data)) {
//                              $this->flash(__('Changes saved succesfully.', true), array('action' => 'view/'.$id));
//                              $this->flash(__('Changes saved succesfully.', true));
		                $this->redirect('/emails/view/'.$id);

                        } else {
                        }
                }
                if (empty($this->data)) {
                        $this->data = $this->Email->read(null, $id);
                }

                $this->set('relevanceoptions', array( '0'=>'0', '1'=>'1', '2'=>'2',  '3'=>'3', '4'=>'4', '5'=>'5', '100'=> __('Unknown', true)));


        }


// *****************************************************************************************************
        function eml() {
            $id = $this->Session->read('emailid');
            if (!$id) {
                $this->redirect('/users/login');
            }
            else {
                $this->Email->recursive = -1;
                $email = $this->Email->read(null, $id);
                $this->autoRender = false;
                header("Content-Disposition: attachment; filename=mail".$id.".eml");
                header("Content-Type: message/rfc822");
                header("Content-Length: " . filesize($email['Email']['mime_path']));
                readfile($email['Email']['mime_path']);
                exit();
            }
        }

// *****************************************************************************************************
        function info() {
            $id = $this->Session->read('emailid');
            if (!$id) {
                $this->redirect('/users/login');
            }
            else {
                $this->Email->recursive = -1;
                $email = $this->Email->read(null, $id);
                $this->autoRender = false;
                header("Content-Disposition: filename=info".$id.".xml");
                header("Content-Type: application/xhtml+xml; charset=utf-8");
                header("Content-Length: " . filesize($email['Email']['flow_info']));
                readfile($email['Email']['flow_info']);
                exit();
            }
        }

// *****************************************************************************************************
        function content($path=null) {
            $tmp_dir = $this->Session->read('mimedir');
            if (!$path || !$tmp_dir) {
                exit();
            }
            $this->autoRender = false;
            header("Content-Type: binary");
            readfile($tmp_dir."/".$path);
            //echo $path;
            exit();
        }

// *****************************************************************************************************
        function pcap() {
            $id = $this->Session->read('emailid');
            if (!$id) {
                $this->redirect('/users/login');
            }
            else {
                $this->Email->recursive = -1;
                $email = $this->Email->read(null, $id);
                $file_pcap = "/tmp/email_".time()."_".$id.".pcap";
                $this->Xml2Pcap->doPcap($file_pcap, $email['Email']['flow_info']);
                $this->autoRender = false;
                header("Content-Disposition: filename=email_".$id.".pcap");
                header("Content-Type: binary");
                header("Content-Length: " . filesize($file_pcap));
                @readfile($file_pcap);
                unlink($file_pcap);
                exit();
            }
        }
}
?>
