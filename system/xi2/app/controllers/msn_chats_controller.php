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

uses('sanitize');

class MsnChatsController extends AppController {

    var $name = 'MsnChats';
    var $uses = array('Msn_chat');
    var $helpers = array('Html', 'Form', 'Javascript');
    var $components = array('Xml2Pcap', 'Xplico');
    var $paginate = array('limit' => 16, 'order' => array('Msn_chat.capture_date' => 'desc'));

    function beforeFilter() {
        $groupid = $this->Session->read('group');
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if (!$groupid || !$polid || !$solid) {
            $this->redirect('/users/login');
        }
    }

    function index($id = null) {
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        $this->Msn_chat->recursive = -1;
        $filter = array('Msn_chat.sol_id' => $solid);
        // host 
        $host_id = $this->Session->read('host_id');
        if (!empty($host_id) && $host_id["host"] != 0) {
            $filter['Msn_chat.source_id'] = $host_id["host"];
        }
        $srch = null;
        if ($this->Session->check('srch_msn')) {
            $srch = $this->Session->read('srch_msn');
        }
        if ($this->data) {
            $srch = $this->data['Search']['label'];
        }
        if (!empty($srch)) {
            $filter['Msn_chat.chat LIKE'] = "%$srch%";
        }
        $msgs = $this->paginate('Msn_chat', $filter);
        $this->Session->write('srch_msn', $srch);
        $this->set('msn_chats', $msgs);
        $this->set('srchd', $srch);
        $this->set('menu_left', $this->Xplico->leftmenuarray(6) );
    }

    function info($id = null) {
        if (!$id) {
            die();
        }
        else {
            $this->Msn_chat->recursive = -1;
            $msn_chat = $this->Msn_chat->read(null, $id);
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            if ($polid != $msn_chat['Msn_chat']['pol_id'] || $solid != $msn_chat['Msn_chat']['sol_id']) {
                die();
            }
            $this->autoRender = false;
            header("Content-Disposition: filename=info_data".$id.".xml");
            header("Content-Type: application/xhtml+xml; charset=utf-8");
            header("Content-Length: " . filesize($msn_chat['Msn_chat']['flow_info']));
            readfile($msn_chat['Msn_chat']['flow_info']);
            exit();
        }
    }

    function chat($id = null) {
        if (!$id) {
            exit();
        }
        $this->Msn_chat->recursive = -1;
        $chat = $this->Msn_chat->read(null, $id);
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if ($polid != $chat['Msn_chat']['pol_id'] || $solid != $chat['Msn_chat']['sol_id']) {
            die();
        }
        $this->layout = 'fbchat';
        $this->autoRender = TRUE;
        /* in the template there is a JavaScript */
        $this->set('chat_info', $chat['Msn_chat']);
        $talk = '';
        $fp = fopen($chat['Msn_chat']['chat_path'], 'r');
        while (false != ($line = fgets($fp, 4096))) {
            $line = trim($line, "\r\n\0");
            if (stripos($line, '[')  !== false) {
                $talk = $talk.'<label> <script type="text/javascript"> var txt="'.$line.'"; document.write(txt); </script>'."</label>\n";
            }
            else {
                $talk = $talk.'<p> <script type="text/javascript"> var txt="'.$line.'"; document.write(txt); </script>'."</p>\n";
            }
        }
        fclose($fp);
        // register visualization
        if (!$chat['Msn_chat']['first_visualization_user_id']) {
            $uid = $this->Session->read('userid');
            $chat['Msn_chat']['first_visualization_user_id'] = $uid;
            $chat['Msn_chat']['viewed_date'] = date("Y-m-d H:i:s");
            $this->Msn_chat->save($chat);
        }
                
        $this->set('chat', $talk);
    }

    function pcap($id = null) {
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if (!$id) {
            die();
        }
        else {
            $this->Msn_chat->recursive = -1;
            $msn_chat = $this->Msn_chat->read(null, $id);
            if ($polid != $msn_chat['Msn_chat']['pol_id'] || $solid != $msn_chat['Msn_chat']['sol_id']) {
                die();
            }
            $flow_info = $msn_chat['Msn_chat']['flow_info'];
        }
        $file_pcap = "/tmp/paltalk_".time()."_".$id.".pcap";
        $this->Xml2Pcap->doPcap($file_pcap, $flow_info);
        $this->autoRender = false;
        header("Content-Disposition: filename=paltalk_".$id.".pcap");
        header("Content-Type: binary");
        header("Content-Length: " . filesize($file_pcap));
        @readfile($file_pcap);
        unlink($file_pcap);
        exit();
    }
}
?>
