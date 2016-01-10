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

uses('sanitize');

class MmsController extends AppController {
        var $name = 'Mms';
        var $uses = array('Mm', 'Mmscontent');
        var $helpers = array('Html', 'Form', 'Javascript');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Mm.capture_date' => 'desc'));

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
            $this->Mm->recursive = -1;
            $filter = array('Mm.sol_id' => $solid);
            // host selezionato
            $host_id = $this->Session->read('host_id');
            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Mm.source_id'] = $host_id["host"];
            }
            $srch = null;
            if ($this->Session->check('srch_mms')) {
                $srch = $this->Session->read('srch_mms');
            }
            if ($this->data) {
                $srch = $this->data['Search']['label'];
            }
            if (!empty($srch)) {
                $filter['OR'] = array();
                $filter['OR']['Mm.from_num LIKE'] = "%$srch%";
                $filter['OR']['Mm.to_num LIKE'] = "%$srch%";
            }
            $msgs = $this->paginate('Mm', $filter);
            $this->Session->write('srch_mms', $srch);
            $this->set('mms', $msgs);
            $this->set('srchd', $srch);
            $this->set('menu_left', $this->Xplico->leftmenuarray(5) );
        }

        function view($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->set('menu_left', $this->Xplico->leftmenuarray(5) );
                $this->Mm->recursive = -1;
                $mm = $this->Mm->read(null, $id);
                if ($polid != $mm['Mm']['pol_id'] || $solid != $mm['Mm']['sol_id']) {
                    $this->redirect('/users/login');
                }
                //print_r($mm);

                $this->Session->write('mmid', $id);
                $this->set('mm', $mm);

                /* files */
                $this->Mmscontent->recursive = -1;
                $this->set('mmscontent', $this->Mmscontent->find('all', array('conditions' => ("sol_id = $solid AND mm_id = $id"))));
                // register visualization
                if (!$mm['Mm']['first_visualization_user_id']) {
                    $uid = $this->Session->read('userid');
                    $mm['Mm']['first_visualization_user_id'] = $uid;
                    $mm['Mm']['viewed_date'] = date("Y-m-d H:i:s");
                    $this->Mm->save($mm);
                }
        }

        function info($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mm->recursive = -1;
            $mm = $this->Mm->read(null, $id);
            if ($polid != $mm['Mm']['pol_id'] || $solid != $mm['Mm']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=info".$id.".xml");
                header("Content-Type: application/xhtml+xml; charset=utf-8");
                header("Content-Length: " . filesize($mm['Mm']['flow_info']));
                readfile($mm['Mm']['flow_info']);
                exit();
            }
        }

        function data_file($id_data = null) {
            $id = $this->Session->read('mmid');
            if (!$id || !$id_data) {
                exit();
            }
            else {
                $this->Mmscontent->recursive = -1;
                $mm_data = $this->Mmscontent->read(null, $id_data);
                if ( $mm_data['Mmscontent']['mm_id'] == $id) {
                    $this->autoRender = false;
                    header("Content-Disposition: filename=" . $mm_data['Mmscontent']['filename']);
                    header("Content-Type: " . $mm_data['Mmscontent']['content_type']);
                    header("Content-Length: " . filesize($mm_data['Mmscontent']['file_path']));
                    readfile($mm_data['Mmscontent']['file_path']);
                    //print_r($mm_data);
                }
                exit();
            }
        }

        function pcap($id = null) {
            if (!$id) {
                $id = $this->Session->read('mmid');
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Mm->recursive = -1;
            $mm = $this->Mm->read(null, $id);
            if ($polid != $mm['Mm']['pol_id'] || $solid != $mm['Mm']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $file_pcap = "/tmp/mms_".time()."_".$id.".pcap";
                $this->Xml2Pcap->doPcap($file_pcap, $mm['Mm']['flow_info']);
                $this->autoRender = false;
                header("Content-Disposition: filename=mms_".$id.".pcap");
                header("Content-Type: binary");
                header("Content-Length: " . filesize($file_pcap));
                @readfile($file_pcap);
                unlink($file_pcap);
                exit();
            }
       }
}
?>
