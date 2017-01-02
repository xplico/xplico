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

class ArpsController extends AppController {
        var $name = 'Arps';
        var $helpers = array('Html', 'Form');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Arp.capture_date' => 'desc'));

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
            $this->Arp->recursive = -1;
            $filter = array('Arp.sol_id' => $solid);
            // host selezionato
	    if ($this->Session->check('host_id')) {
	            $host_id = $this->Session->read('host_id');
            }

            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Arp.source_id'] = $host_id["host"];
            }
            $srch = null;
            if ($this->Session->check('srch_arp')) {
                $srch = $this->Session->read('srch_arp');
            }
            if (!empty($this->request->data)) {
                $srch = $this->request->data['Search']['Search'];
            }
            if (!empty($srch)) {
                $filter['OR'] = array();
                $filter['OR']['Arp.mac LIKE'] = "%$srch%";
                $filter['OR']['Arp.ip LIKE'] = "%$srch%";
            }
            $arp_msgs = $this->paginate('Arp', $filter);
            $this->Session->write('srch_arp', $srch);
            $this->set('arp_msgs', $arp_msgs);
            $this->set('srchd', $srch);
            $this->set('menu_left', $this->Xplico->leftmenuarray(1));
        }

        function info($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Arp->recursive = -1;
                $arp_message = $this->Arp->read(null, $id);
                if ($polid != $arp_message['Arp']['pol_id'] || $solid != $arp_message['Arp']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    $this->autoRender = false;
                    header("Content-Disposition: filename=info".$id.".xml");
                    header("Content-Type: application/xhtml+xml; charset=utf-8");
                    header("Content-Length: " . filesize($arp_message['Arp']['flow_info']));
                    readfile($arp_message['Arp']['flow_info']);
                    exit();
                }
        }
}
?>
