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
   * Portions created by the Initial Developer are Copyright (C) 2009
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
require_once 'php-ofc-library/open-flash-chart.php';

class DnsMessagesController extends AppController {
        var $name = 'DnsMessages';
        var $helpers = array('Html', 'Form', 'Javascript', 'Session');
        var $components = array('Xml2Pcap', 'Xplico', 'Session');
        var $paginate = array('limit' => 16, 'order' => array('DnsMessage.capture_date' => 'desc'));

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
                $this->DnsMessage->recursive = -1;
                $filter = array('DnsMessage.sol_id' => $solid);
                // host selezionato

		 if ($this->Session->check('host_id')) {
	                $host_id = $this->Session->read('host_id');
                }

                if ( (!empty($host_id)) && ($host_id["host"] != 0) ) {
                    $filter['DnsMessage.source_id'] = $host_id["host"];
                }
                $srch = null;
                if ($this->Session->check('srch_dns')) {
                    $srch = $this->Session->read('srch_dns');
                }
                if (!empty($this->data)) {
                    $srch = $this->data['Search']['Search'];
                }
                if (!empty($srch)) {
                    $filter['OR'] = array();
                    $filter['OR']['DnsMessage.hostname LIKE'] 	= "%$srch%";
                    $filter['OR']['DnsMessage.cname LIKE']	= "%$srch%";
                    $filter['OR']['DnsMessage.ip LIKE'] 	= "%$srch%";
                    $this->Session->write('srch_dns', $srch);
                }
                $dns_msgs = $this->paginate('DnsMessage', $filter);
                $this->Session->write('srch_dns', $srch);
                $this->set('dns_msgs', $dns_msgs);
                $this->set('srchd', $srch);
                $this->set('menu_left', $this->Xplico->leftmenuarray(1));
        }

        function graph() {
                $solid = $this->Session->read('sol');
                $host_id = $this->Session->read('host_id');
                $host_srch = "";
                if (!empty($host_id) && $host_id != 0) {
                    $host_srch = " AND source_id = ".$host_id;
                }
                $this->DnsMessage->recursive = -1;
                $tmp = $this->DnsMessage->find('all', array('conditions' => ("sol_id = $solid".$host_srch), 'order' => 'DnsMessage.capture_date DESC'));
                //echo $tmp[0]['DnsMessage']['capture_date'].' ';
                if (!empty($tmp)) {
                    $data_max = strtotime($tmp[0]['DnsMessage']['capture_date']);
                    $tmp = $this->DnsMessage->find('all', array('conditions' => ("sol_id = $solid AND capture_date > '1971-10-10 10:10:10'".$host_srch), 'order' => 'DnsMessage.capture_date ASC'));
                    //echo $tmp[0]['DnsMessage']['capture_date'].' ';
                    $data_min = strtotime($tmp[0]['DnsMessage']['capture_date']);
                    $delta_t = $data_max - $data_min;
                }
                $graph_time_base = array(__('min', true), __('hours', true), __('days', true), __('weeks', true), __('months', true), __('years', true));
                $graph_time_base_v = array(60, 3600, 86400, -1, -2, -3);
                $i = 0;
                if ($delta_t/60 > 100) {
                    $i = 1;
                }
                if ($delta_t/3600 > 100) {
                    $i = 2;
                }
                if ($delta_t/604800 > 100) {
                    $i = 3;
                }
                if ($delta_t/604800*4 > 100) {
                    $i = 4;
                }
                $graph_time_name = array();
                $graph_time_value = array();
                for (; $i!=6; $i++) {
                    $graph_time_name[] = $graph_time_base[$i];
                    $graph_time_value[] = $graph_time_base_v[$i];
                }

		//var_dump($this->data);
                if (!empty($this->data)) {
                    $checked = array();
                    $graph_time = $graph_time_value[$this->data['formtime']['timeinterval']];
                }
                else {
                    $checked = array('value'=>0);
                    $graph_time = $graph_time_value[0];
                }
                $this->Session->write('graph_time', $graph_time);
                $this->set('dns_gpage_url', '/dns_messages/site_graph');
                $this->set('checked', $checked);
                $this->set('time_list', $graph_time_name);
                $this->set('menu_left', $this->Xplico->leftmenuarray(1) );

        }

        function site_graph() {
                $solid = $this->Session->read('sol');
                $this->set('dns_gpage_url', '/dns_messages/graph');
                $this->set('menu_left', $this->Xplico->leftmenuarray(1) );
        }

        function info($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->DnsMessage->recursive = -1;
                $dns_message = $this->DnsMessage->read(null, $id);
                if ($polid != $dns_message['DnsMessage']['pol_id'] || $solid != $dns_message['DnsMessage']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    $this->autoRender = false;
                    header("Content-Disposition: filename=info".$id.".xml");
                    header("Content-Type: application/xhtml+xml; charset=utf-8");
                    header("Content-Length: " . filesize($dns_message['DnsMessage']['flow_info']));
                    readfile($dns_message['DnsMessage']['flow_info']);
                    exit();
                }
        }

        function pcap($id = null) {
            if (!$id) {
                die();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->DnsMessage->recursive = -1;
            $dns = $this->DnsMessage->read(null, $id);
            if ($polid != $dns['DnsMessage']['pol_id'] || $solid != $dns['DnsMessage']['sol_id']) {
                    $this->redirect('/users/login');
                }
            else {
                $file_pcap = "/tmp/email_".time()."_".$id.".pcap";
                $this->Xml2Pcap->doPcap($file_pcap, $dns['DnsMessage']['flow_info']);
                $this->autoRender = false;
                header("Content-Disposition: filename=dns_".$id.".pcap");
                header("Content-Type: binary");
                header("Content-Length: " . filesize($file_pcap));
                @readfile($file_pcap);
                unlink($file_pcap);
                exit();
            }
        }

        function gdata() {
            date_default_timezone_set('UTC');
            $this->autoRender = false;
            $solid = $this->Session->read('sol');
            $host_id = $this->Session->read('host_id');
            $tinterval = $this->Session->read('graph_time');
            $host_srch = "";
            if (!empty($host_id) && $host_id != 0) {
                $host_srch = " AND source_id = ".$host_id;
            }

            $this->DnsMessage->recursive = -1;
            $tmp = $this->DnsMessage->find('all', array('conditions' => ("sol_id = $solid".$host_srch), 'order' => 'DnsMessage.capture_date DESC'));
            $data_max = $tmp[0]['DnsMessage']['capture_date'];
            $tmp = $this->DnsMessage->find('all', array('conditions' => ("sol_id = $solid AND capture_date > '1971-10-10 10:10:10'".$host_srch), 'order' => 'DnsMessage.capture_date ASC'));
            $data_min = $tmp[0]['DnsMessage']['capture_date'];
            $time_min = strtotime($data_min);
            $time_max = strtotime($data_max);
            if ($tinterval > 0) {
                $time_min = ((int)($time_min/$tinterval)*$tinterval);
                $time_max = ((int)($time_max/$tinterval)*$tinterval)+$tinterval;
                $int_a = $time_min;
                $int_b = $time_min + $tinterval;
            }
            else {
                if ($tinterval == -1) {
                    // week
                    $time_min = ((int)(($time_min-(date('w', $time_min)*(24*3600)))/(24*3600)))*(24*3600);
                    $int_a = $time_min;
                    $int_b = $time_min + (7*24*3600);
                    //echo $data_min.'-->'.date('Y-m-d H:i:s', $int_a).' '.date('Y-m-d H:i:s', $int_b).' ';
                }
                elseif ($tinterval == -2) {
                    // month
                    $month = date('m', $time_min);
                    $year = date('o', $time_min);
                    $int_a = strtotime($year.'-'.$month.'-01 00:00:00');
                    $month++;
                    if ($month == 13) {
                        $year++;
                        $month = 1;
                    }
                    if ($month < 10)
                        $int_b = strtotime($year.'-0'.$month.'-01 00:00:00');
                    else
                        $int_b = strtotime($year.'-'.$month.'-01 00:00:00');
                }
                else {
                    // year
                    $year = date('o', $time_min);
                    $int_a = strtotime($year.'-01-01 00:00:00');
                    $year++;
                    $int_b = strtotime($year.'-01-01 00:00:00');
                }
            }
            
            $data = array();
            $x = array();
            $first = true;
            $max_resp = 0;
            while ($int_a < $time_max) {
                $sint_a = date('Y-m-d H:i:s', $int_a);
                $sint_b = date('Y-m-d H:i:s', $int_b);
                $tmp = (int)$this->DnsMessage->find('count', array('conditions' => ("sol_id = $solid AND capture_date >= '$sint_a' AND capture_date < '$sint_b'".$host_srch)));
                $data[] = array($tmp, 0);
                if ($max_resp < $tmp)
                    $max_resp = $tmp;
                if ($tinterval == 3600 || $tinterval == 60) {
                    $label = strstr($sint_a, " ");
                    if (strstr($sint_a, "00:00:00") || $first)
                        $x[] = substr_replace($sint_a, '', 10);
                    else
                        $x[] = substr_replace($label, '', 6);
                }
                elseif ($tinterval == 86400) {
                    $x[] = substr_replace($sint_a, '', 10);
                }
                elseif ($tinterval == -1) {
                    $week = date('W', $int_a);
                    if ($first || $week == 1)
                        $x[] = substr_replace($sint_a, '', 4).' ['.$week.']';
                    else
                        $x[] = $week;
                }
                elseif ($tinterval == -2) {
                    if ($first || $month == 2)
                        $x[] = substr_replace($sint_a, '', 4).' ['.date('M', $int_a).']';
                    else
                        $x[] = date('M', $int_a);
                }
                else {
                    $x[] = substr_replace($sint_a, '', 4);
                }
                $int_a = $int_b;
                if ($tinterval > 0) {
                    $int_b = $int_b + $tinterval;
                }
                else {
                    if ($tinterval == -1) {
                        // week
                        $int_b = $int_b + (7*24*3600); // a week
                    }
                    elseif ($tinterval == -2) {
                        // month
                        $month++;
                        if ($month == 13) {
                            $year++;
                            $month = 1;
                        }
                        if ($month < 10)
                            $int_b = strtotime($year.'-0'.$month.'-01 00:00:00');
                        else
                            $int_b = strtotime($year.'-'.$month.'-01 00:00:00');
                    }
                    else {
                        // year
                        $year++;
                        $int_b = strtotime($year.'-01-01 00:00:00');
                    }
                }
                $first = false;
            }

            $title = new title( __("DNS response", true) );
            $title->set_style( "{font-size: 14px; color: #990000; text-align: center; font-weight:bold;}" );
            
            $bar = new bar_stack();
            $bar->set_colours( array('#E2DF0A', '#577261'));
            $bar->set_on_show(new bar_on_show('grow-up', 0, 0.5));
            $bar->set_values( $data );
            $bar->set_tooltip( "Date: #x_label#<br>Response #val#" );
            $tooltip = new tooltip( );
            $tooltip->set_hover();
            $tooltip->set_shadow( false );
            $tooltip->set_stroke( 5 );
            $tooltip->set_colour( "#6E604F" );
            $tooltip->set_background_colour( "#BDB396" );

            $x_labels = new x_axis_labels();
            $x_labels->rotate(300);
            $x_labels->set_labels( $x );
            
            $x_axis = new x_axis();
            $x_axis->set_labels( $x_labels );
            
            $y = new y_axis();
            $y->set_range( 0, $max_resp*1.1, (int)($max_resp/10) );

            $chart = new open_flash_chart();
            $chart->set_title( $title );
            $chart->add_element( $bar );
            $chart->set_bg_colour( '#F9F9F9' );
            $chart->set_x_axis( $x_axis );
            $chart->set_y_axis( $y );
            $chart->set_tooltip( $tooltip );
            // menu'
            $m = new ofc_menu("#f0E0ff", "#878787");
            $m->values(array(new ofc_menu_item(__('Host Popularity', true),'go_gpage')));
            $chart->set_menu($m);

            header("Content-Type: text/plain");
            echo $chart->toPrettyString(); 

            die();
        }

        function gsitedata() {
            $this->autoRender = false;
            $solid = $this->Session->read('sol');
            $host_id = $this->Session->read('host_id');
            $tinterval = 3600;
            $host_srch = "";
            if (!empty($host_id) && $host_id != 0) {
                $host_srch = " AND source_id = ".$host_id;
            }
            
            $this->DnsMessage->recursive = -1;
            $site_count = $this->DnsMessage->query('SELECT hostname, COUNT(*) FROM dns_messages WHERE sol_id = '.$solid.$host_srch.' GROUP BY hostname ORDER BY COUNT(*) DESC LIMIT 50');
            //sort($site_count);
            $data = array();
            $x = array();
            $max_resp = 0;
            foreach ($site_count as $site) {
                $data[] = array((int)($site[0]['COUNT(*)']), 0);
                if ($max_resp < (int)($site[0]['COUNT(*)']))
                    $max_resp = (int)($site[0]['COUNT(*)']);
                if (empty($site[0]['hostname']))
                    $x[] = (string)($site['dns_messages']['hostname']);
                else
                    $x[] = (string)($site[0]['hostname']);
            }

            // joson data format
            $title = new title( __("Host Popularity", true) );
            $title->set_style( "{font-size: 14px; color: #990000; text-align: center; font-weight:bold;}" );
            
            $bar = new bar_stack();
            $bar->set_colours( array('#e77919', '#577261') );
            $bar->set_on_show(new bar_on_show('grow-up', 0, 0.5));
            $bar->set_values( $data );
            $bar->set_tooltip( 'Host: #x_label#<br>Response #val#<br>' );
            $tooltip = new tooltip( );
            $tooltip->set_hover();
            $tooltip->set_shadow( false );
            $tooltip->set_stroke( 5 );
            $tooltip->set_colour( "#6E604F" );
            $tooltip->set_background_colour( "#BDB396" );
            
            $data_labels = new x_axis_labels();
            $data_labels->rotate(90);
            $data_labels->set_labels( $x );
            
            $x_axis = new x_axis();
            $x_axis->set_labels( $data_labels );
            
            $y = new y_axis();
            $y->set_range( 0, $max_resp*1.1, (int)($max_resp/10) );

            $chart = new open_flash_chart();
            $chart->set_bg_colour( '#F9F9F9' );
            $chart->set_title( $title );
            $chart->add_element( $bar );
            $chart->set_x_axis( $x_axis );
            $chart->set_y_axis( $y );
            $chart->set_tooltip( $tooltip );
            // menu'
            $m = new ofc_menu("#f0E0ff", "#878787");
            $m->values(array(new ofc_menu_item(__('DNS Response', true),'go_gpage')));
            $chart->set_menu($m);

            header("Content-Type: text/plain");
            echo $chart->toPrettyString(); 
            die();
        }
}
?>
