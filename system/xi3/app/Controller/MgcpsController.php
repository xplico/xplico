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


class MgcpsController extends AppController {
        var $name = 'Mgcps';
        var $helpers = array('Html', 'Form');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Mgcp.capture_date' => 'desc'));

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
            $this->Mgcp->recursive = -1;
            $filter = array('Mgcp.sol_id' => $solid);
            // host selezionato
            $host_id = $this->Session->read('host_id');
            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Mgcp.source_id'] = $host_id["host"];
            }
            $srch = null;
            if ($this->Session->check('srch_mgcp')) {
                $srch = $this->Session->read('srch_mgcp');
            }
            if (!empty($this->request->data)) {
                $srch = $this->request->data['Search']['label'];
            }
            if (!empty($srch)) {
                $filter['OR'] = array();
                $filter['OR']['Mgcp.from_addr LIKE'] = "%$srch%";
                $filter['OR']['Mgcp.to_addr LIKE'] = "%$srch%";
            }
            $msgs = $this->paginate('Mgcp', $filter);
            $this->Session->write('srch_mgcp', $srch);
            $this->set('mgcps', $msgs);
            $this->set('srchd', $srch);
            $this->set('menu_left', $this->Xplico->leftmenuarray(4) );
        }

        function view($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->set('menu_left', $this->Xplico->leftmenuarray(4) );
                $this->Mgcp->recursive = -1;
                $mgcp = $this->Mgcp->read(null, $id);
                if ($polid != $mgcp['Mgcp']['pol_id'] || $solid != $mgcp['Mgcp']['sol_id']) {
                    $this->redirect('/users/login');
                }

                $this->Session->write('mgcpid', $id);
                $this->set('mgcp', $mgcp);

                // register visualization
                if (!$mgcp['Mgcp']['first_visualization_user_id']) {
                    $uid = $this->Session->read('userid');
                    $mgcp['Mgcp']['first_visualization_user_id'] = $uid;
                    $mgcp['Mgcp']['viewed_date'] = date("Y-m-d H:i:s");
                    $this->Mgcp->save($mgcp);
                }
        }

        function caller_play($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mgcp->recursive = -1;
            $mgcp = $this->Mgcp->read(null, $id);
            if ($polid != $mgcp['Mgcp']['pol_id'] || $solid != $mgcp['Mgcp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->layout = 'voip';
                $this->autoRender = TRUE;
                $this->set('mgcp_id', $id);
            }
        }

        function called_play($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mgcp->recursive = -1;
            $mgcp = $this->Mgcp->read(null, $id);
            if ($polid != $mgcp['Mgcp']['pol_id'] || $solid != $mgcp['Mgcp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->layout = 'voip';
                $this->autoRender = TRUE;
                $this->set('mgcp_id', $id);
            }
        }

        function info($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mgcp->recursive = -1;
            $mgcp = $this->Mgcp->read(null, $id);
            if ($polid != $mgcp['Mgcp']['pol_id'] || $solid != $mgcp['Mgcp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=info".$id.".xml");
                header("Content-Type: application/xhtml+xml; charset=utf-8");
                header("Content-Length: " . filesize($mgcp['Mgcp']['flow_info']));
                readfile($mgcp['Mgcp']['flow_info']);
                exit();
            }
        }

        function caller($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mgcp->recursive = -1;
            $mgcp = $this->Mgcp->read(null, $id);
            if ($polid != $mgcp['Mgcp']['pol_id'] || $solid != $mgcp['Mgcp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=caller".$id.".mp3");
                header("Content-Length: " . filesize($mgcp['Mgcp']['ucaller']));
                header("Content-Type: audio/mpeg");
                readfile($mgcp['Mgcp']['ucaller']);
                exit();
            }
        }

        function called($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mgcp->recursive = -1;
            $mgcp = $this->Mgcp->read(null, $id);
            if ($polid != $mgcp['Mgcp']['pol_id'] || $solid != $mgcp['Mgcp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=called".$id.".mp3");
                header("Content-Length: " . filesize($mgcp['Mgcp']['ucalled']));
                header("Content-Type: audio/mpeg");
                readfile($mgcp['Mgcp']['ucalled']);
                exit();
            }
        }

        function mix($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mgcp->recursive = -1;
            $mgcp = $this->Mgcp->read(null, $id);
            if ($polid != $mgcp['Mgcp']['pol_id'] || $solid != $mgcp['Mgcp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=mix".$id.".mp3");
                header("Content-Length: " . filesize($mgcp['Mgcp']['umix']));
                header("Content-Type: audio/mpeg");
                readfile($mgcp['Mgcp']['umix']);
                exit();
            }
        }

        function cmds($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mgcp->recursive = -1;
            $mgcp = $this->Mgcp->read(null, $id);
            if ($polid != $mgcp['Mgcp']['pol_id'] || $solid != $mgcp['Mgcp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=mgcp_cmds".$id.".txt");
                header("Content-Length: " . filesize($mgcp['Mgcp']['commands']));
                header("Content-Type: text");
                readfile($mgcp['Mgcp']['commands']);
                exit();
            }
        }

        function pcap($id = null) {
            if (!$id) {
                $id = $this->Session->read('mgcpid');
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mgcp->recursive = -1;
            $mgcp = $this->Mgcp->read(null, $id);
            if ($polid != $mgcp['Mgcp']['pol_id'] || $solid != $mgcp['Mgcp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $file_pcap = "/tmp/mgcps_".time()."_".$id.".pcap";
                $this->Xml2Pcap->doPcap($file_pcap, $mgcp['Mgcp']['flow_info']);
                $this->autoRender = false;
                header("Content-Disposition: filename=mgcp_".$id.".pcap");
                header("Content-Type: binary");
                header("Content-Length: " . filesize($file_pcap));
                @readfile($file_pcap);
                unlink($file_pcap);
                exit();
            }
       }
}
?>
