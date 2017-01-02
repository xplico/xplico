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

App::uses('Sanitize', 'Utility');


class PaltalkExpsController extends AppController {

    var $name = 'PaltalkExps';
    var $uses = array('Paltalk_exp');
    var $helpers = array('Html', 'Form');
    var $components = array('Xml2Pcap', 'Xplico');
    var $paginate = array('limit' => 16, 'order' => array('Paltalk_exp.capture_date' => 'desc'));

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
        $this->Paltalk_exp->recursive = -1;
        $filter = array('Paltalk_exp.sol_id' => $solid);
        // host 
        $host_id = $this->Session->read('host_id');
        if (!empty($host_id) && $host_id["host"] != 0) {
            $filter['Paltalk_exp.source_id'] = $host_id["host"];
        }
        $srch = null;
        if ($this->Session->check('srch_pltke')) {
            $srch = $this->Session->read('srch_pltke');
        }
        if ($this->request->data) {
            $srch = $this->request->data['Search']['label'];
        }
        if (!empty($srch)) {
            $filter['Paltalk_exp.user_nick LIKE'] = "%$srch%";
        }
        $msgs = $this->paginate('Paltalk_exp', $filter);
        $this->Session->write('srch_pltke', $srch);
        $this->set('paltalk_exps', $msgs);
        $this->set('srchd', $srch);
        $this->set('menu_left', $this->Xplico->leftmenuarray(6) );
    }

    function info($id = null) {
        if (!$id) {
            die();
        }
        else {
            $this->Paltalk_exp->recursive = -1;
            $paltalk_exp = $this->Paltalk_exp->read(null, $id);
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            if ($polid != $paltalk_exp['Paltalk_exp']['pol_id'] || $solid != $paltalk_exp['Paltalk_exp']['sol_id']) {
                $this->redirect('/users/login');
            }
            $this->autoRender = false;
            header("Content-Disposition: filename=info".$id.".xml");
            header("Content-Type: application/xhtml+xml; charset=utf-8");
            header("Content-Length: " . filesize($paltalk_exp['Paltalk_exp']['flow_info']));
            readfile($paltalk_exp['Paltalk_exp']['flow_info']);
            exit();
        }
    }

    function chat($id = null) {
        if (!$id) {
            exit();
        }
        $this->Paltalk_exp->recursive = -1;
        $chat = $this->Paltalk_exp->read(null, $id);
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if ($polid != $chat['Paltalk_exp']['pol_id'] || $solid != $chat['Paltalk_exp']['sol_id']) {
            die();
        }
        $this->layout = 'fbchat';
        $this->autoRender = TRUE;
        /* in the template there is a JavaScript */
        $this->set('chat_info', $chat['Paltalk_exp']);
        $talk = '';
        $fp = fopen($chat['Paltalk_exp']['channel_path'], 'r');
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
        if (!$chat['Paltalk_exp']['first_visualization_user_id']) {
            $uid = $this->Session->read('userid');
            $chat['Paltalk_exp']['first_visualization_user_id'] = $uid;
            $chat['Paltalk_exp']['viewed_date'] = date("Y-m-d H:i:s");
            $this->Paltalk_exp->save($chat);
        }
            
        $this->set('chat', $talk);
    }

    function pcap($id = null) {
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if (!$id) {
            $id = $this->Session->read('paltalk_expid');
        }
        if (!$id)
            die();
        $this->Paltalk_exp->recursive = -1;
        $paltalk_exp = $this->Paltalk_exp->read(null, $id);
        if ($polid != $paltalk_exp['Paltalk_exp']['pol_id'] || $solid != $paltalk_exp['Paltalk_exp']['sol_id']) {
            die();
        }
        $flow_info = $paltalk_exp['Paltalk_exp']['flow_info'];
        $file_pcap = "/tmp/paltalk_exp_".time()."_".$id.".pcap";
        $this->Xml2Pcap->doPcap($file_pcap, $flow_info);
        $this->autoRender = false;
        header("Content-Disposition: filename=paltalk_exp_".$id.".pcap");
        header("Content-Type: binary");
        header("Content-Length: " . filesize($file_pcap));
        @readfile($file_pcap);
        unlink($file_pcap);
        exit();
    }
}
?>
