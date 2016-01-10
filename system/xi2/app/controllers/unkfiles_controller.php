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
   * Portions created by the Initial Developer are Copyright (C) 2011
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


class UnkfilesController extends AppController {

        var $name = 'Unkfiles';
        var $helpers = array('Html', 'Form', 'Javascript');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Unkfile.capture_date' => 'desc'));

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
            $this->Unkfile->recursive = -1;
            $filter = array('Unkfile.sol_id' => $solid);
            // host selezionato
            $host_id = $this->Session->read('host_id');
            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Unkfile.source_id'] = $host_id["host"];
            }
            $srch = null;
            if ($this->Session->check('srch_teln')) {
                $srch = $this->Session->read('srch_teln');
            }
            if (!empty($this->data)) {
                $srch = $this->data['Unkfiles']['search'];
            }
            if (!empty($srch)) {
                $filter['OR'] = array();
                $filter['OR']['Unkfile.hosts LIKE'] = "%$srch%";
            }
            $msgs = $this->paginate('Unkfile', $filter);
            $this->Session->write('srch_teln', $srch);
            $this->set('unkfiles', $msgs);
            $this->set('srchd', $srch);
            $this->set('menu_left', $this->Xplico->leftmenuarray(8) );
	}

	function bin($id = null) {
            if (!$id) {
                exit();
            }
            
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Unkfile->recursive = -1;
            $unkfile = $this->Unkfile->read(null, $id);
            if ($polid != $unkfile['Unkfile']['pol_id'] || $solid != $unkfile['Unkfile']['sol_id']) {
                die();
            }
            $this->autoRender = false;
            header("Content-Disposition: filename=".$unkfile['Unkfile']['file_name']);
            header("Content-Type: binary");
            header("Content-Length: " . $unkfile['Unkfile']['fsize']);
            readfile($unkfile['Unkfile']['file_path']);
            exit();
        }

        function info($id = null) {
            if (!$id) {
                exit();
            }
            else {
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Unkfile->recursive = -1;
                $unkfile = $this->Unkfile->read(null, $id);
                if ($polid != $unkfile['Unkfile']['pol_id'] || $solid != $unkfile['Unkfile']['sol_id']) {
                    die();
                }
                $this->autoRender = false;
                header("Content-Disposition: filename=info".$id.".xml");
                header("Content-Type: application/xhtml+xml; charset=utf-8");
                header("Content-Length: " . filesize($unkfile['Unkfile']['flow_info']));
                readfile($unkfile['Unkfile']['flow_info']);
                exit();
            }
        }
        
        function pcap($id = null) {
            if (!$id) {
                exit();
            }
            else {
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Unkfile->recursive = -1;
                $unkfile = $this->Unkfile->read(null, $id);
                if ($polid != $unkfile['Unkfile']['pol_id'] || $solid != $unkfile['Unkfile']['sol_id']) {
                    die();
                }
                $file_pcap = "/tmp/unkfile_".time()."_".$id.".pcap";
                $this->Xml2Pcap->doPcap($file_pcap, $unkfile['Unkfile']['flow_info']);
                $this->autoRender = false;
                header("Content-Disposition: filename=unkfile_".$id.".pcap");
                header("Content-Type: binary");
                header("Content-Length: " . filesize($file_pcap));
                @readfile($file_pcap);
                unlink($file_pcap);
                exit();
            }
        }
}
?>
