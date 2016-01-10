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

class PjlsController extends AppController {
        var $name = 'Pjls';
        var $helpers = array('Html', 'Form', 'Javascript');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Pjl.capture_date' => 'desc'));

        function beforeFilter() {
                $groupid = $this->Session->read('group');
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                if (!$groupid || !$polid || !$solid) {
                    $this->redirect('/users/login');
                }
        }

        function index() {
            $solid = $this->Session->read('sol');
            $this->Pjl->recursive = -1;
            $filter = array('Pjl.sol_id' => $solid);
            // host selezionato
            $host_id = $this->Session->read('host_id');
            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Pjl.source_id'] = $host_id["host"];
            }
            $msgs = $this->paginate('Pjl', $filter);
            $this->set('pjls', $msgs);
            $this->set('menu_left', $this->Xplico->leftmenuarray(5) );
        }

        function view($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Pjl->recursive = -1;
                $pjl = $this->Pjl->read(null, $id);
                if ($polid != $pjl['Pjl']['pol_id'] || $solid != $pjl['Pjl']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    // register visualization
                    if (!$pjl['Pjl']['first_visualization_user_id']) {
                        $uid = $this->Session->read('userid');
                        $pjl['Pjl']['first_visualization_user_id'] = $uid;
                        $pjl['Pjl']['viewed_date'] = date("Y-m-d H:i:s");
                        $this->Pjl->save($pjl);
                    }
                    if ($pjl['Pjl']['pdf_size'] != 0) {
                        $this->autoRender = false;
                        header("Content-Type: " . "bin");
                        header("Content-Length: " . $pjl['Pjl']['pdf_size']);
                        readfile($pjl['Pjl']['pdf_path']);
                    }
                    exit();
                }
        }

        function info($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Pjl->recursive = -1;
                $pjl = $this->Pjl->read(null, $id);
                if ($polid != $pjl['Pjl']['pol_id'] || $solid != $pjl['Pjl']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    $this->autoRender = false;
                    header("Content-Disposition: filename=info".$id.".xml");
                    header("Content-Type: application/xhtml+xml; charset=utf-8");
                    header("Content-Length: " . filesize($pjl['Pjl']['flow_info']));
                    readfile($pjl['Pjl']['flow_info']);
                    exit();
                }
        }

        function pcap($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Pjl->recursive = -1;
                $pjl = $this->Pjl->read(null, $id);
                if ($polid != $pjl['Pjl']['pol_id'] || $solid != $pjl['Pjl']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    $file_pcap = "/tmp/pjl_".time()."_".$id.".pcap";
                    $this->Xml2Pcap->doPcap($file_pcap, $pjl['Pjl']['flow_info']);
                    $this->autoRender = false;
                    header("Content-Disposition: filename=pjl_".$id.".pcap");
                    header("Content-Type: binary");
                    header("Content-Length: " . filesize($file_pcap));
                    @readfile($file_pcap);
                    unlink($file_pcap);
                    exit();
                }
        }
}
?>
