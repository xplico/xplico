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

require_once 'commonlib.php';
App::uses('Sanitize', 'Utility');

class FeedsController extends AppController {
        var $name = 'Feeds';
        var $uses = array('Feed', 'Feed_xml');
        var $helpers = array('Html', 'Form');
        var $components = array('Xml2Pcap', 'Xplico');
        var $paginate = array('limit' => 16, 'order' => array('Feed.name' => 'asc'));

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
            $this->Feed->recursive = -1;
            $filter = array('Feed.sol_id' => $solid);
            // host selezionato
 	    if ($this->Session->check('host_id')) {
	            $host_id = $this->Session->read('host_id');
            }

            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Feed.source_id'] = $host_id["host"];
            }
            $srch = null;
            if ($this->Session->check('srch_feed')) {
                $srch = $this->Session->read('srch_feed');
            }
            if ($this->request->data) {
                $srch = $this->request->data['Search']['label'];
            }
            if (!empty($srch)) {
                $filter['OR'] = array();
                $filter['OR']['Feed.name LIKE'] = "%$srch%";
                $filter['OR']['Feed.site LIKE'] = "%$srch%";
            }
            $msgs = $this->paginate('Feed', $filter);
            $this->Session->write('srch_feed', $srch);
            $this->set('feeds', $msgs);
            $this->set('srchd', $srch);
            $this->set('srchd', $srch);
            $this->set('menu_left', $this->Xplico->leftmenuarray(2) );
        }

        function view($id = null) {
            if (!$id) {
                if (!$this->Session->check('feedid'))
                    exit();
                else
                    $id = $this->Session->read('feedid');
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->set('menu_left', $this->Xplico->leftmenuarray(2) );
            $this->Feed->recursive = -1;
            $feed = $this->Feed->read(null, $id);
            if ($polid != $feed['Feed']['pol_id'] || $solid != $feed['Feed']['sol_id']) {
                $this->redirect('/users/login');
                die();
            }
            
            $this->Session->write('feedid', $id);
            $this->set('feed', $feed);
            
            /* files */
            $this->Feed_xml->recursive = -1;
            $filter = array('Feed_xml.sol_id' => $solid);
            // host selezionato
            $host_id = $this->Session->read('host_id');
            if (!empty($host_id) && $host_id["host"] != 0) {
                $filter['Feed_xml.source_id'] = $host_id["host"];
            }
            $filter['Feed_xml.feed_id'] = $id;
            $this->paginate['order'] = array('Feed_xml.capture_date' => 'desc');
            $msgs = $this->paginate('Feed_xml', $filter);
            $this->set('feeds_xml', $msgs);
        }

        function info($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Feed_xml->recursive = -1;
            $feed = $this->Feed_xml->read(null, $id);
            if ($polid != $feed['Feed_xml']['pol_id'] || $solid != $feed['Feed_xml']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $this->autoRender = false;
                header("Content-Disposition: filename=info".$id.".xml");
                header("Content-Type: application/xhtml+xml; charset=utf-8");
                header("Content-Length: " . filesize($feed['Feed_xml']['flow_info']));
                readfile($feed['Feed_xml']['flow_info']);
                exit();
            }
        }

        function xml($id_data = null) {
            $id = $this->Session->read('feedid');
            if (!$id || !$id_data) {
                exit();
            }
            else {
                $this->Feed_xml->recursive = -1;
                $feed_data = $this->Feed_xml->read(null, $id_data);
                if ( $feed_data['Feed_xml']['feed_id'] == $id) {
                    $this->layout = 'rdf';
                    $this->autoRender = TRUE;
                    $xml_file = $feed_data['Feed_xml']['rs_body'];
                    $fp = fopen($feed_data['Feed_xml']['rs_header'], 'r');
                    while (false != ($line = fgets($fp, 4096))) {
                        if (stripos($line, "Content-Encoding:") !== false) {
                            if (stristr($line, "gzip") !== false) {
                                $new_xml_file = "/tmp/rdf_".$id_data;
                                $execute = "cp ".$xml_file." ".$new_xml_file.".gz; gunzip ".$new_xml_file.".gz";
                                system($execute);
                                $xml_file = $new_xml_file;
                            }
                        }
                    }
                    fclose($fp);
                    $rdf = Common_Display($xml_file, 25, true, true, true);
                    $this->set('rdf', $rdf);
                    if (!empty($new_xml_file))
                        unlink($new_xml_file);
/*
                    $this->autoRender = false;
                    header("Content-Disposition: filename=" . 'xml');
                    $fp = fopen($feed_data['Feed_xml']['rs_header'], 'r');
                    while (false != ($line = fgets($fp, 4096))) {
                        if (stripos($line, "Content-Type") !== false)
                            $ct = $line;
                        if (stripos($line, "Content-Encoding:") !== false)
                            $ce = $line;
                    }
                    fclose($fp);
                    if (!empty($ct))
                        header($ct);
                    if (!empty($ce))
                        header($ce);
                    header("Content-Length: " . filesize($feed_data['Feed_xml']['rs_body']));
                    readfile($feed_data['Feed_xml']['rs_body']);
                    //print_r($feed_data);
*/
                }
            }
        }

        function pcap($id = null) {
            if (!$id) {
                $id = $this->Session->read('feedid');
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Feed_xml->recursive = -1;
            $feed = $this->Feed_xml->read(null, $id);
            if ($polid != $feed['Feed_xml']['pol_id'] || $solid != $feed['Feed_xml']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $file_pcap = "/tmp/feeds_".time()."_".$id.".pcap";
                $this->Xml2Pcap->doPcap($file_pcap, $feed['Feed_xml']['flow_info']);
                $this->autoRender = false;
                header("Content-Disposition: filename=feeds_".$id.".pcap");
                header("Content-Type: binary");
                header("Content-Length: " . filesize($file_pcap));
                @readfile($file_pcap);
                unlink($file_pcap);
                exit();
            }
       }
}
?>
