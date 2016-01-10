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



class IrcsController extends AppController {

    var $name = 'Ircs';
    var $uses = array('Irc', 'Irc_channel');
    var $helpers = array('Html', 'Form', 'Javascript');
    var $components = array('Xml2Pcap', 'Xplico');
    var $paginate = array('limit' => 16, 'order' => array('Irc.url' => 'asc'));

    function beforeFilter() {
        $groupid = $this->Session->read('group');
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if (!$groupid || !$polid || !$solid) {
            $this->redirect('/users/login');
        }
    }

    function index($id = null) {
        $solid = $this->Session->read('sol');
        $this->Irc->recursive = -1;
        $filter = array('Irc.sol_id' => $solid);
        // host selezionato
        $host_id = $this->Session->read('host_id');
        if (!empty($host_id) && $host_id["host"] != 0) {
            $filter['Irc.source_id'] = $host_id["host"];
        }
        $srch = null;
        if ($this->Session->check('srch_irc')) {
            $srch = $this->Session->read('srch_irc');
        }
        if ($this->data) {
            $srch = $this->data['Search']['label'];
        }
        if (!empty($srch)) {
            $filter['Irc.url LIKE'] = "%$srch%";
        }
        $msgs = $this->paginate('Irc', $filter);
        $this->Session->write('srch_irc', $srch);
        $this->set('ircs', $msgs);
        $this->set('srchd', $srch);
        $this->set('menu_left', $this->Xplico->leftmenuarray(6) );
    }

    function view($id = null) {
        if (!$id) {
            if (!$this->Session->check('ircid'))
                $this->redirect('/users/login');
            else
                $id = $this->Session->read('ircid');
        }
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');

        $this->set('menu_left', $this->Xplico->leftmenuarray(6) );
        $this->Irc->recursive = -1;
        $irc = $this->Irc->read(null, $id);
        if ($polid != $irc['Irc']['pol_id'] || $solid != $irc['Irc']['sol_id']) {
            $this->redirect('/users/login');
        }
        $this->Session->write('ircid', $id);
        $this->set('irc', $irc);
        
        /* files */
        $this->Irc_channel->recursive = -1;
        $filter = array('Irc_channel.sol_id' => $solid);
        $filter['Irc_channel.irc_id'] = $id;
        $this->paginate['order'] =  array('Irc_channel.capture_date' => 'desc');
        $msgs = $this->paginate('Irc_channel', $filter);
        $this->set('irc_channel', $msgs);
        // register visualization
        if (!$irc['Irc']['first_visualization_user_id']) {
            $uid = $this->Session->read('userid');
            $irc['Irc']['first_visualization_user_id'] = $uid;
            $irc['Irc']['viewed_date'] = date("Y-m-d H:i:s");
            $this->Irc->save($irc);
        }
    }

    function cmd() {
        $id = $this->Session->read('ircid');
        if (!$id) {
            $this->redirect('/users/login');
        }
        else {
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Irc->recursive = -1;
            $irc = $this->Irc->read(null, $id);
            if ($polid != $irc['Irc']['pol_id'] || $solid != $irc['Irc']['sol_id']) {
                $this->redirect('/users/login');
            }
            $this->autoRender = false;
            header("Content-Disposition: filename=irc_cmd_".$id.".txt");
            header("Content-Type: text");
            header("Content-Length: " . filesize($irc['Irc']['cmd_path']));
            readfile($irc['Irc']['cmd_path']);
            exit();
        }
    }

    function info() {
        $id = $this->Session->read('ircid');
        if (!$id) {
            $this->redirect('/users/login');
        }
        else {
            $this->Irc->recursive = -1;
            $irc = $this->Irc->read(null, $id);
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            if ($polid != $irc['Irc']['pol_id'] || $solid != $irc['Irc']['sol_id']) {
                $this->redirect('/users/login');
            }
            $this->autoRender = false;
            header("Content-Disposition: filename=info".$id.".xml");
            header("Content-Type: application/xhtml+xml; charset=utf-8");
            header("Content-Length: " . filesize($irc['Irc']['flow_info']));
            readfile($irc['Irc']['flow_info']);
            exit();
        }
    }

    function info_channel($id_data = null) {
        $id = $this->Session->read('ircid');
        if (!$id || !$id_data) {
            die();
        }
        else {
            $this->Irc_channel->recursive = -1;
            $irc_channel = $this->Irc_channel->read(null, $id_data);
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            if ($polid != $irc_channel['Irc_channel']['pol_id'] || $solid != $irc_channel['Irc_channel']['sol_id']) {
                die();
            }
            $this->autoRender = false;
            header("Content-Disposition: filename=info_data".$id_data.".xml");
            header("Content-Type: application/xhtml+xml; charset=utf-8");
            header("Content-Length: " . filesize($irc_channel['Irc_channel']['flow_info']));
            readfile($irc_channel['Irc_channel']['flow_info']);
            exit();
        }
    }

    function channel($id = null) {
        if (!$id) {
            exit();
        }
        $this->Irc_channel->recursive = -1;
        $chat = $this->Irc_channel->read(null, $id);
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if ($polid != $chat['Irc_channel']['pol_id'] || $solid != $chat['Irc_channel']['sol_id']) {
            die();
        }
        $this->layout = 'fbchat';
        $this->autoRender = TRUE;
        /* in the template there is a JavaScript */
        $this->set('channel', $chat['Irc_channel']);
        $talk = '';
        $fp = fopen($chat['Irc_channel']['channel_path'], 'r');
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
        if (!$chat['Irc_channel']['first_visualization_user_id']) {
            $uid = $this->Session->read('userid');
            $chat['Irc_channel']['first_visualization_user_id'] = $uid;
            $chat['Irc_channel']['viewed_date'] = date("Y-m-d H:i:s");
            $this->Irc_channel->save($chat);
        }
                
        $this->set('chat', $talk);
    }

    function pcap($id = null) {
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if (!$id) {
            $id = $this->Session->read('ircid');
            if (!$id)
                die();
            $this->Irc->recursive = -1;
            $irc = $this->Irc->read(null, $id);
            if ($polid != $irc['Irc']['pol_id'] || $solid != $irc['Irc']['sol_id']) {
                die();
            }
            $flow_info = $irc['Irc']['flow_info'];
        }
        else {
            $this->Irc_channel->recursive = -1;
            $irc_channel = $this->Irc_channel->read(null, $id);
            if ($polid != $irc_channel['Irc_channel']['pol_id'] || $solid != $irc_channel['Irc_channel']['sol_id']) {
                die();
            }
            $flow_info = $irc_channel['Irc_channel']['flow_info'];
        }
        $file_pcap = "/tmp/irc_".time()."_".$id.".pcap";
        $this->Xml2Pcap->doPcap($file_pcap, $flow_info);
        $this->autoRender = false;
        header("Content-Disposition: filename=irc_".$id.".pcap");
        header("Content-Type: binary");
        header("Content-Length: " . filesize($file_pcap));
        @readfile($file_pcap);
        unlink($file_pcap);
        exit();
    }
}
?>
