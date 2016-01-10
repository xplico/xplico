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

class RtpsController extends AppController {
        var $name = 'Rtps';
        var $helpers = array('Html', 'Form', 'Javascript');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Rtp.capture_date' => 'desc'));

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
            $this->Rtp->recursive = -1;
            $filter = array('Rtp.sol_id' => $solid);
            // host selezionato
            $host_id = $this->Session->read('host_id');
            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Rtp.source_id'] = $host_id["host"];
            }
            $srch = null;
            if ($this->Session->check('srch_rtp')) {
                $srch = $this->Session->read('srch_rtp');
            }
            if ($this->data) {
                $srch = $this->data['Search']['label'];
            }
            if (!empty($srch)) {
                $filter['OR'] = array();
                $filter['OR']['RTP.from_addr LIKE'] = "%$srch%";
                $filter['OR']['RTP.to_addr LIKE'] = "%$srch%";
            }
            $msgs = $this->paginate('Rtp', $filter);
            $this->Session->write('srch_rtp', $srch);
            $this->set('rtps', $msgs);
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
                $this->Rtp->recursive = -1;
                $rtp = $this->Rtp->read(null, $id);
                if ($polid != $rtp['Rtp']['pol_id'] || $solid != $rtp['Rtp']['sol_id']) {
                    $this->redirect('/users/login');
                }

                $this->Session->write('rtpid', $id);
                $this->set('rtp', $rtp);

                // register visualization
                if (!$rtp['Rtp']['first_visualization_user_id']) {
                    $uid = $this->Session->read('userid');
                    $rtp['Rtp']['first_visualization_user_id'] = $uid;
                    $rtp['Rtp']['viewed_date'] = date("Y-m-d H:i:s");
                    $this->Rtp->save($rtp);
                }
        }

        function caller_play($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Rtp->recursive = -1;
            $rtp = $this->Rtp->read(null, $id);
            if ($polid != $rtp['Rtp']['pol_id'] || $solid != $rtp['Rtp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->layout = 'voip';
                $this->autoRender = TRUE;
                $this->set('rtp_id', $id);
            }
        }

        function called_play($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Rtp->recursive = -1;
            $rtp = $this->Rtp->read(null, $id);
            if ($polid != $rtp['Rtp']['pol_id'] || $solid != $rtp['Rtp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->layout = 'voip';
                $this->autoRender = TRUE;
                $this->set('rtp_id', $id);
            }
        }

        function info($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Rtp->recursive = -1;
            $rtp = $this->Rtp->read(null, $id);
            if ($polid != $rtp['Rtp']['pol_id'] || $solid != $rtp['Rtp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=info".$id.".xml");
                header("Content-Type: application/xhtml+xml; charset=utf-8");
                header("Content-Length: " . filesize($rtp['Rtp']['flow_info']));
                readfile($rtp['Rtp']['flow_info']);
                exit();
            }
        }

        function caller($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Rtp->recursive = -1;
            $rtp = $this->Rtp->read(null, $id);
            if ($polid != $rtp['Rtp']['pol_id'] || $solid != $rtp['Rtp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=caller".$id.".mp3");
                header("Content-Length: " . filesize($rtp['Rtp']['ucaller']));
                header("Content-Type: audio/mpeg");
                readfile($rtp['Rtp']['ucaller']);
                exit();
            }
        }

        function called($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Rtp->recursive = -1;
            $rtp = $this->Rtp->read(null, $id);
            if ($polid != $rtp['Rtp']['pol_id'] || $solid != $rtp['Rtp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=called".$id.".mp3");
                header("Content-Length: " . filesize($rtp['Rtp']['ucalled']));
                header("Content-Type: audio/mpeg");
                readfile($rtp['Rtp']['ucalled']);
                exit();
            }
        }

        function mix($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Rtp->recursive = -1;
            $rtp = $this->Rtp->read(null, $id);
            if ($polid != $rtp['Rtp']['pol_id'] || $solid != $rtp['Rtp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=mix".$id.".mp3");
                header("Content-Length: " . filesize($rtp['Rtp']['umix']));
                header("Content-Type: audio/mpeg");
                readfile($rtp['Rtp']['umix']);
                exit();
            }
        }

        function pcap($id = null) {
            if (!$id) {
                $id = $this->Session->read('rtpid');
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Rtp->recursive = -1;
            $rtp = $this->Rtp->read(null, $id);
            if ($polid != $rtp['Rtp']['pol_id'] || $solid != $rtp['Rtp']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $file_pcap = "/tmp/rtps_".time()."_".$id.".pcap";
                $this->Xml2Pcap->doPcap($file_pcap, $rtp['Rtp']['flow_info']);
                $this->autoRender = false;
                header("Content-Disposition: filename=rtp_".$id.".pcap");
                header("Content-Type: binary");
                header("Content-Length: " . filesize($file_pcap));
                @readfile($file_pcap);
                unlink($file_pcap);
                exit();
            }
       }
}
?>
