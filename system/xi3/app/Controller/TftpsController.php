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

App::uses('Sanitize', 'Utility');

class TftpsController extends AppController {

        var $name = 'Tftps';
        var $uses = array('Tftp', 'Tftp_file');
        var $helpers = array('Html', 'Form');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Tftp.capture_date' => 'desc'));

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
            $this->Tftp->recursive = -1;
            $filter = array('Tftp.sol_id' => $solid);
            // host selezionato
            $host_id = $this->Session->read('host_id');
            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Tftp.source_id'] = $host_id["host"];
            }
            $srch = null;
            if ($this->Session->check('srch_tftp')) {
                $srch = $this->Session->read('srch_tftp');
            }
            if ($this->request->data) {
                $srch = $this->request->data['Search']['label'];
            }
            if (!empty($srch)) {
                $filter['OR'] = array();
                $filter['OR']['Tftp.url LIKE'] = "%$srch%";
            }
            $msgs = $this->paginate('Tftp', $filter);
            $this->Session->write('srch_tftp', $srch);
            $this->set('tftps', $msgs);
            $this->set('srchd', $srch);
            $this->set('menu_left', $this->Xplico->leftmenuarray(5) );

        }

        function view($id = null) {
            if (!$id) {
                if (!$this->Session->check('tftpid'))
                    $this->redirect('/users/login');
                else
                    $id = $this->Session->read('tftpid');
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->set('menu_left', $this->Xplico->leftmenuarray(5) );
            
            $this->Tftp->recursive = -1;
            $tftp = $this->Tftp->read(null, $id);
            if ($polid != $tftp['Tftp']['pol_id'] || $solid != $tftp['Tftp']['sol_id']) {
                $this->redirect('/users/login');
            }
            $this->Session->write('tftpid', $id);
            $this->set('tftp', $tftp);
            
            /* files */
            $this->Tftp_file->recursive = -1;
            $filter = array('Tftp_file.sol_id' => $solid);
            $filter['Tftp_file.tftp_id'] = $id;
            $this->paginate['order'] =  array('Tftp_file.capture_date' => 'desc');
            $msgs = $this->paginate('Tftp_file', $filter);
            $this->set('tftp_file', $msgs);

            // register visualization
            if (!$tftp['Tftp']['first_visualization_user_id']) {
                $uid = $this->Session->read('userid');
                $tftp['Tftp']['first_visualization_user_id'] = $uid;
                $tftp['Tftp']['viewed_date'] = date("Y-m-d H:i:s");
                $this->Tftp->save($tftp);
            }
        }

        function cmd() {
            $id = $this->Session->read('tftpid');
            if (!$id) {
                $this->redirect('/users/login');
            }
            else {
                $this->Tftp->recursive = -1;
                $tftp = $this->Tftp->read(null, $id);
                $this->autoRender = false;
                header("Content-Disposition: filename=tftp_cmd".$id.".txt");
                header("Content-Type: text");
                header("Content-Length: " . filesize($tftp['Tftp']['cmd_path']));
                readfile($tftp['Tftp']['cmd_path']);
                exit();
            }
        }

        function info() {
            $id = $this->Session->read('tftpid');
            if (!$id) {
                $this->redirect('/users/login');
            }
            else {
                $this->Tftp->recursive = -1;
                $tftp = $this->Tftp->read(null, $id);
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                if ($polid != $tftp['Tftp']['pol_id'] || $solid != $tftp['Tftp']['sol_id']) {
                    $this->redirect('/users/login');
                }
                $this->autoRender = false;
                header("Content-Disposition: filename=info".$id.".xml");
                header("Content-Type: application/xhtml+xml; charset=utf-8");
                header("Content-Length: " . filesize($tftp['Tftp']['flow_info']));
                readfile($tftp['Tftp']['flow_info']);
                exit();
            }
        }

        function info_data($id_data = null) {
            $id = $this->Session->read('tftpid');
            if (!$id || !$id_data) {
                die();
            }
            else {
                $this->Tftp_file->recursive = -1;
                $tftp_file = $this->Tftp_file->read(null, $id_data);
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                if ($polid != $tftp_file['Tftp_file']['pol_id'] || $solid != $tftp_file['Tftp_file']['sol_id']) {
                    die();
                }
                $this->autoRender = false;
                header("Content-Disposition: filename=info_data".$id_data.".xml");
                header("Content-Type: application/xhtml+xml; charset=utf-8");
                header("Content-Length: " . filesize($tftp_file['Tftp_file']['flow_info']));
                readfile($tftp_file['Tftp_file']['flow_info']);
                exit();
            }
        }

        function data_file($id_data = null) {
            $id = $this->Session->read('tftpid');
            if (!$id || !$id_data) {
                $this->redirect('/users/login');
            }
            else {
                $this->Tftp_file->recursive = -1;
                $tftp_data = $this->Tftp_file->read(null, $id_data);
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                if ($polid != $tftp_data['Tftp_file']['pol_id'] || $solid != $tftp_data['Tftp_file']['sol_id']) {
                    die();
                }
                $this->autoRender = false;
                header("Content-Disposition: filename=" . $tftp_data['Tftp_file']['filename']);
                header("Content-Type: bin");
                header("Content-Length: " . filesize($tftp_data['Tftp_file']['file_path']));
                readfile($tftp_data['Tftp_file']['file_path']);
                //print_r($tftp_data);
                exit();
            }
        }

        function pcap($id = null) {
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            if (!$id) {
                $id = $this->Session->read('tftpid');
                if (!$id)
                    die();
                $this->Tftp->recursive = -1;
                $tftp = $this->Tftp->read(null, $id);
                if ($polid != $tftp['Tftp']['pol_id'] || $solid != $tftp['Tftp']['sol_id']) {
                    die();
                }
                $flow_info = $tftp['Tftp']['flow_info'];
            }
            else {
                $this->Tftp_file->recursive = -1;
                $tftp_file = $this->Tftp_file->read(null, $id);
                if ($polid != $tftp_file['Tftp_file']['pol_id'] || $solid != $tftp_file['Tftp_file']['sol_id']) {
                    die();
                }
                $flow_info = $tftp_file['Tftp_file']['flow_info'];
            }
            $file_pcap = "/tmp/tftp_".time()."_".$id.".pcap";
            $this->Xml2Pcap->doPcap($file_pcap, $flow_info);
            $this->autoRender = false;
            header("Content-Disposition: filename=tftp_".$id.".pcap");
            header("Content-Type: binary");
            header("Content-Length: " . filesize($file_pcap));
            @readfile($file_pcap);
            unlink($file_pcap);
            exit();
       }
}
?>
