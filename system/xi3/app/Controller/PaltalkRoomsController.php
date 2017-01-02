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

class PaltalkRoomsController extends AppController {

    var $name = 'PaltalkRooms';
    var $uses = array('Paltalk_room');
    var $helpers = array('Html', 'Form');
    var $components = array('Xml2Pcap', 'Xplico');
    var $paginate = array('limit' => 16, 'order' => array('Paltalk_room.capture_date' => 'desc'));

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
        $this->Paltalk_room->recursive = -1;
        $filter = array('Paltalk_room.sol_id' => $solid);
        // host 
        $host_id = $this->Session->read('host_id');
        if (!empty($host_id) && $host_id["host"] != 0) {
            $filter['Paltalk_room.source_id'] = $host_id["host"];
        }
        $srch = null;
        if ($this->Session->check('srch_pltk')) {
            $srch = $this->Session->read('srch_pltk');
        }
        if ($this->request->data) {
            $srch = $this->request->data['Search']['label'];
        }
        if (!empty($srch)) {
            $filter['Paltalk_room.room LIKE'] = "%$srch%";
        }
        $msgs = $this->paginate('Paltalk_room', $filter);
        $this->Session->write('srch_pltk', $srch);
        $this->set('paltalk_rooms', $msgs);
        $this->set('srchd', $srch);
        $this->set('menu_left', $this->Xplico->leftmenuarray(6) );
    }

    function info($id = null) {
        if (!$id) {
            die();
        }
        else {
            $this->Paltalk_room->recursive = -1;
            $paltalk_room = $this->Paltalk_room->read(null, $id);
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            if ($polid != $paltalk_room['Paltalk_room']['pol_id'] || $solid != $paltalk_room['Paltalk_room']['sol_id']) {
                die();
            }
            $this->autoRender = false;
            header("Content-Disposition: filename=info_data".$id.".xml");
            header("Content-Type: application/xhtml+xml; charset=utf-8");
            header("Content-Length: " . filesize($paltalk_room['Paltalk_room']['flow_info']));
            readfile($paltalk_room['Paltalk_room']['flow_info']);
            exit();
        }
    }

    function room($id = null) {
        if (!$id) {
            exit();
        }
        $this->Paltalk_room->recursive = -1;
        $room = $this->Paltalk_room->read(null, $id);
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if ($polid != $room['Paltalk_room']['pol_id'] || $solid != $room['Paltalk_room']['sol_id']) {
            die();
        }
        $this->layout = 'fbchat';
        $this->autoRender = TRUE;
        /* in the template there is a JavaScript */
        $this->set('room_info', $room['Paltalk_room']);
        $talk = '';
        $fp = fopen($room['Paltalk_room']['room_path'], 'r');
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
        if (!$room['Paltalk_room']['first_visualization_user_id']) {
            $uid = $this->Session->read('userid');
            $room['Paltalk_room']['first_visualization_user_id'] = $uid;
            $room['Paltalk_room']['viewed_date'] = date("Y-m-d H:i:s");
            $this->Paltalk_room->save($room);
        }
                
        $this->set('room', $talk);
    }

    function pcap($id = null) {
        $polid = $this->Session->read('pol');
        $solid = $this->Session->read('sol');
        if (!$id) {
            die();
        }
        else {
            $this->Paltalk_room->recursive = -1;
            $paltalk_room = $this->Paltalk_room->read(null, $id);
            if ($polid != $paltalk_room['Paltalk_room']['pol_id'] || $solid != $paltalk_room['Paltalk_room']['sol_id']) {
                die();
            }
            $flow_info = $paltalk_room['Paltalk_room']['flow_info'];
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
