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
class WebsController extends AppController {
        var $name = 'Webs';
        var $helpers = array('Html', 'Form');
        var $components = array('Xml2Pcap', 'Xplico');
        var $uses = array('Web', 'Sol');
        var $paginate = array('limit' => 16, 'order' => array('Web.capture_date' => 'desc'));
        
        function beforeFilter() {
                //$this->layout = 'default';
                $groupid = $this->Session->read('group');
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                if (!$groupid || !$polid || !$solid) {
                    $bheader = $_SERVER['HTTP_HOST'];
                    if (stripos($bheader, 'localhost') !== false || stripos($bheader, $_SERVER['SERVER_ADDR']) !== false) {
                        $this->redirect('/users/login');
                    }
                    else {
                        // proxy functionality
                    }
                }
        }

        function index($id = null) {
                $uri = $_SERVER['REQUEST_URI'];
                $i = stripos($uri, "http://");
                if ($i === false) {
                    $this->Session->setFlash(__('For a complete view of html page set your browser to use Proxy, and point it to Web server.'));
                }
                else {
                    $this->Session->setFlash(__('This version can be inaccurate in displaying Web pages.'));
                }
                $this->Session->delete('host');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $filter = array('Web.sol_id' => $solid);
                // host selezionato
                if ($this->Session->check('host_id')) {
                    $host_id = $this->Session->read('host_id');
                }

                if ((!empty($host_id)) && ($host_id["host"] != 0)) {
                    $filter['Web.source_id'] = $host_id["host"];
                }
                if (!$this->Session->check('filtr')) {
                    $filtr = 'text/html%';
                    $value = 0;
                    $rsrc_url = null;
                }
                else {
                    $filtr = $this->Session->read('filtr');
                    $value = $this->Session->read('checked');
                    $rsrc_url = $this->Session->read('srch');
                }
                if (!empty($this->request->data)) {
                    $value = $this->request->data['webcontent']['type'];
                    switch ($value) {
                    case 0:
                        $filtr = 'text/html%';
                        break;

                    case 1:
                        $filtr = 'image%';
                        break;

                    case 2:
                        $filtr = '%flash%';
                        break;

                    case 3:
                        $filtr = '%video%';
                        break;

                    case 4:
                        $filtr = '%audio%';
                        break;

                    case 5:
                        $filtr = '%json%';
                        break;

                    default:
                        $filtr = '%';
                        break;
                    }
                    if ($this->request->data['webcontent']['search'] != "") {                        
                        $rsrc_url = $this->request->data['webcontent']['search'];
                    }
                    else
                        $rsrc_url = null;
                }
                if ($rsrc_url != null) {
                    $filter['Web.content_type LIKE'] = $filtr;
                    $filter['OR'] = array();
                    $filter['OR']['Web.url LIKE'] = '%'.$rsrc_url.'%';
                    $filter['OR']['Web.agent LIKE'] = '%'.$rsrc_url.'%';
                }
                else {
                    $filter['Web.content_type LIKE'] = $filtr;
                }
                $webs_list = $this->paginate('Web', $filter);
                $this->Session->write('filtr', $filtr);
                $this->Session->write('checked', $value);
                $this->Session->write('srch', $rsrc_url);
                $this->set('webs', $webs_list);
                $this->set('checked', $value);
                $this->set('srchd', $rsrc_url);
                $this->set('menu_left', $this->Xplico->leftmenuarray(2) );
        }
        
        
        function images($id = null) {
                $this->paginate = array('limit' => 12, 'order' => array('Web.capture_date' => 'desc'));

                $uri = $_SERVER['REQUEST_URI'];
                $i = stripos($uri, "http://");
                $this->Session->delete('host');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $filter = array('Web.sol_id' => $solid, 'Web.content_type LIKE' => '%image%');
                // host selezionato
                if ($this->Session->check('host_idd')) {
                    $host_id = $this->Session->read('host_id');
                }
                if (!empty($host_id) && $host_id["host"] != 0) {
                    $filter['Web.source_id'] = $host_id["host"];
                }
                $rsrc_url = null;
                if ($this->Session->check('srchi')) {
                    $rsrc_url = $this->Session->read('srchi');
                }
                if (!empty($this->request->data)) {
                    $rsrc_url = $this->request->data['Search']['label'];
                    $this->Session->write('srchi', $rsrc_url);
                }
                if ($rsrc_url != null) {
                    $filter['Web.url LIKE'] = '%'.$rsrc_url.'%';
                }
                else {
                    $rsrc_url = '';
                }
                $images_list = $this->paginate('Web', $filter);
                $this->set('images', $images_list);
                $this->set('srchd', $rsrc_url);
                $this->set('menu_left', $this->Xplico->leftmenuarray(2));
        }

        
        function imgpage($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Web->recursive = -1;
            $web = $this->Web->read(null, $id);
            if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                /* find reference */
                $fp = fopen($web['Web']['rq_header'], 'r');
                while (false != ($line = fgets($fp, 4096))) {
                    if (stripos($line, "Referer:") !== false) {
                        fclose($fp);
                        $ref = trim(strstr($line, "http://"), "\r\n");
                        $ref = substr($ref, 7); // delete http://
                        $cdate = $web['Web']['capture_date'];
                        $webp = $this->Web->find('first', array('conditions' => ("pol_id = $polid AND sol_id <= $solid AND capture_date <= '$cdate' AND url LIKE '%$ref%' AND response!='304'")));
                        if (!empty($webp)) {
                            $this->redirect('/webs/view/'.$webp['Web']['id']);
                        }
                        else {
                            /* it is not correctc but time (capture_date) in sqlite2 is bad of +/- ~1 sec */
                            $webp = $this->Web->find('first', array('conditions' => ("pol_id = $polid AND sol_id <= $solid AND capture_date > '$cdate' AND url LIKE '%$ref%' AND response!='304'")));
                            if (!empty($webp)) {
                                $this->redirect('/webs/view/'.$webp['Web']['id']);
                            }
                            else {
                                $this->redirect('/webs/view/'.$web['Web']['id']);
                            }
                        }
                        die();
                    }
                }
                fclose($fp);
                $this->redirect('/webs/view/'.$web['Web']['id']);
                die();
            }
        }

        
        function view($id = null) {
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $web = null;
                $uri = $_SERVER['REQUEST_URI'];
                if (is_numeric($id) && stripos($uri, '/webs/view/'.$id) !== false) {
                    $web = $this->Web->read(null, $id);
                    if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id'])
                        exit();
                }
                if (empty($web)) {
                    $url = substr($uri, 7); // delete http://
                    // ricerca se e' la pagina della redirezione (se presente)
                    $filename = '/tmp/'.md5($uri.$_SERVER['REMOTE_ADDR']).'.ref';
                    if (file_exists($filename)) {
                        $fp = fopen($filename, 'r');
                        $ref = fread($fp, 10240);
                        fclose($fp);
                        unlink($filename);
                        $this->redirect($ref);
                        die();
                    }
                    else {
                        // ricerca se e' la pagina principale (l'url cliccato)
                        $filename = '/tmp/'.md5($uri.$_SERVER['REMOTE_ADDR']).'.id';
                        if (file_exists($filename)) {
                            $fp = fopen($filename, 'r');
                            $id = fread($fp, 100);
                            fclose($fp);
                            unlink($filename);
                            $web = $this->Web->read(null, $id);
                            
                            /* per debug
                            $fp = fopen('/tmp/url.txt', 'aw');
                            fwrite($fp, $url."\r\n\r\n");
                            fclose($fp);
                            */

                            // recupero Content-Type e Content-Encoding
                            if (file_exists($web['Web']['rs_header'])) {
                                $this->autoRender = false;
                                $fp = fopen($web['Web']['rs_header'], 'r');
                                if ($fp != false) {
                                    while (false != ($line = fgets($fp, 4096))) {
                                        if (stripos($line, "Content-Type") !== false)
                                            $ct = $line;
                                        if (stripos($line, "Content-Encoding:") !== false)
                                            $ce = $line;
                                    }
                                    fclose($fp);
                                }
                                else {
/* debug
                                    print_r($id);
                                    print_r($uri);
                                    print_r($web);
*/
                                }
                                if (!empty($ct))
                                    header($ct);
                                if (!empty($ce))
                                    header($ce);
                                // recupero lunghezza
                                $size = $web['Web']['rs_bd_size'];
                                header("Content-Length: " . $size);
                                if ($size != 0)
                                    readfile($web['Web']['rs_body']);
                            }
                            exit();
                        }
                    }
                    // sessioni sulle quali eseguire la ricerca
                    $filename = '/tmp/'.$_SERVER['REMOTE_ADDR'].'.sid';
                    if (file_exists($filename)) {
                        $fp = fopen($filename, 'r');
                        $solid = fread($fp, 100);
                        fclose($fp);
                        $this->Sol->recursive = -1;
                        $sol_rec = $this->Sol->read(null, $solid);
                        $polid = $sol_rec['Sol']['pol_id'];
                        $web = $this->Web->find('first', array('conditions' => ("pol_id = $polid AND sol_id <= $solid AND url LIKE '%$url%' AND response!='304'")));
                        /* per debug
                        $fp = fopen('/tmp/url.txt', 'aw');
                        fwrite($fp, "--- ".$url."\r\n");
                        fwrite($fp, "sol: ".$solid." pol: ".$polid."\r\n");
                        fclose($fp);
                        */
                    }
                    if (!empty($web)) {
                        // recupero Content-Type e Content-Encoding
                        if (file_exists($web['Web']['rs_header'])) {
                            $this->autoRender = false;
                            $fp = fopen($web['Web']['rs_header'], 'r');
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
                            // recupero lunghezza
                            $size = $web['Web']['rs_bd_size'];
                            header("Content-Length: " . $size);
                            if ($size != 0)
                                readfile($web['Web']['rs_body']);
                        }
                    }
                    else {
                        /* debug
                        $fp = fopen('/tmp/url.txt', 'aw');
                        fwrite($fp, "--- ".$url."\r\n\r\n");
                        fclose($fp);
                        */
                    }
                    exit();
                }
                else {
                    // register visualization
                    if (!$web['Web']['first_visualization_user_id']) {
                        $uid = $this->Session->read('userid');
                        $web['Web']['first_visualization_user_id'] = $uid;
                        $web['Web']['viewed_date'] = date("Y-m-d H:i:s");
                        $this->Web->save($web);
                    }
                    // se con il proxy lo sfrutto altrimenti visualizzo solo la pagina
                    $uri = $_SERVER['REQUEST_URI'];
                    $i = stripos($uri, "http://");
                    if ($i === false)  {
                        $this->redirect('/webs/resBody/'.$id); // there is the exit at the end of this function
                    }
                    else {
                        // salvo l'id del file contente la pagina principale
                        $filename = md5('http://'.$web['Web']['url'].$_SERVER['REMOTE_ADDR']);
                        $fp = fopen('/tmp/'.$filename.'.id', 'w');
                        fwrite($fp, $id);
                        fclose($fp);
                        
                        // indico il gruppo di sessioni sul quale eseguire la ricerca dei contenuti
                        $filename = $_SERVER['REMOTE_ADDR'];
                        $fp = fopen('/tmp/'.$filename.'.sid', 'w');
                        fwrite($fp, $solid);
                        fclose($fp);
                        // salvo url del reference della pagina, se presente
/* funziona ma e' disabilitata
                        $fp = fopen($web['Web']['rq_header'], 'r');
                        while (false != ($line = fgets($fp, 4096))) {
                            if (stripos($line, "Referer:") !== false) {
                                $ref = trim(strstr($line, "http://"), "\r\n");
                                $file_ref =  md5($ref.$_SERVER['REMOTE_ADDR']);
                                $fpref = fopen('/tmp/'.$file_ref.'.ref', 'w');
                                fwrite($fpref, 'http://'.$web['Web']['url']);
                                fclose($fpref);
                                fclose($fp);
                                $this->redirect($ref);
                                die();
                            }
                        }
                        fclose($fp);
*/
                        // ridireziono sulla pagina principale
                        $this->redirect('http://'.$web['Web']['url']);
                    }
                    exit();
                }
        }

        function method($id = null) {
            if (!$id) {
                echo "Operation not allowed!";
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Web->recursive = -1;
            $web = $this->Web->read(null, $id);

            if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                $this->redirect('/users/login');
            }

            $this->set('menu_left', $this->Xplico->leftmenuarray(2) );

            $message = $this->Web->read(null, $id);
            // recupero degli IP e dei port
            $xml = simplexml_load_file($message['Web']['flow_info']);
            foreach($xml->flow->frame as $frame) {
                if ($frame->frm_type == 'tcp') {
                    foreach($frame as $prop) {
                        if ($prop->name == 'tcp.srcport') {
                            $src_ip_port = $prop->value;
                        }
                        else if ($prop->name == 'tcp.dstport') {
                            $dst_ip_port = $prop->value;
                        }
                    }
                }
                else if ($frame->frm_type == 'ip') {
                    foreach($frame as $prop) {
                        if ($prop->name == 'ip.src') {
                            $src_ip_port = $prop->value .':'. $src_ip_port;
                        }
                        else if ($prop->name == 'ip.dst') {
                            $dst_ip_port = $prop->value .':'. $dst_ip_port;
                        }
                    }
                    break;
                }
            }
            // passaggio dei valori
            $this->set('message', $message);
            $this->set('src_ip_port', $src_ip_port);
            $this->set('dst_ip_port', $dst_ip_port);
        }

        function play($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $web = $this->Web->read(null, $id);

                if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    if (!$web['Web']['first_visualization_user_id']) {
                        $uid = $this->Session->read('userid');
                        $web['Web']['first_visualization_user_id'] = $uid;
                        $web['Web']['viewed_date'] = date("Y-m-d H:i:s");
                        $this->Web->save($web);
                    }
                    $this->set('menu_left', $this->Xplico->leftmenuarray(2) );
                    $message = $this->Web->read(null, $id);
                    $this->set('message', $message);
                }
        }

        function info($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $web = $this->Web->read(null, $id);
                if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    $this->autoRender = false;
                    header("Content-Disposition: filename=info".$id.".xml");
                    header("Content-Type: application/xhtml+xml; charset=utf-8");
                    header("Content-Length: " . filesize($web['Web']['flow_info']));
                    readfile($web['Web']['flow_info']);
                    exit();
                }
        }

        function reqHeader($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $web = $this->Web->read(null, $id);
                if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    if (file_exists($web['Web']['rq_header'])) {
                        $size = filesize($web['Web']['rq_header']);
                        $this->autoRender = false;
                        header("Content-Disposition: filename=req_header".$id.".txt");
                        header("Content-Type: text");
                        header("Content-Length: " . $size);
                        readfile($web['Web']['rq_header']);
                    }
                    exit();
                }
        }

        function resHeader($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $web = $this->Web->read(null, $id);
                if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    if (file_exists($web['Web']['rs_header'])) {
                        $size = filesize($web['Web']['rs_header']);
                        $this->autoRender = false;
                        header("Content-Disposition: filename=res_header".$id.".txt");
                        header("Content-Type: text");
                        header("Content-Length: " . $size);
                        readfile($web['Web']['rs_header']);
                    }
                    exit();
                }
        }


        function reqBody($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $web = $this->Web->read(null, $id);
                if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    if ($web['Web']['rq_bd_size'] != 0) {
                        $this->autoRender = false;
                        header("Content-Disposition: filename=req_body".$id.".bin");
                        // recupero Content-Type e Content-Encoding
                        /*
                        $fp = fopen($web['Web']['rq_header'], 'r');
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
                        */
                        header("Content-Length: " . filesize($web['Web']['rq_body']));
                        readfile($web['Web']['rq_body']);
                    }
                    exit();
                }
        }

        function resBody($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $web = $this->Web->read(null, $id);
                if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                    if (strstr($_SERVER['HTTP_REFERER'], '/webs/resBody') != false) {
                        die();
                    }
                    $this->redirect('/users/login');
                }
                else {
                    if ($web['Web']['response'] == '304') {
                        $ref = $web['Web']['url'];
                        $cdate = $web['Web']['capture_date'];
                        $webp = $this->Web->find('first', array('conditions' => ("pol_id = $polid AND sol_id <= $solid AND capture_date <= '$cdate' AND url LIKE '%$ref%' AND response != '304'")));
                        if (!empty($webp)) {
                            $this->redirect('/webs/resBody/'.$webp['Web']['id']);
                        }
                    }
                    else if ($web['Web']['rs_bd_size'] != 0) {
                        $this->autoRender = false;
                        header("Content-Disposition: filename=res_body".$id.".bin");
                        // recupero Content-Type e Content-Encoding e Location
                        $fp = fopen($web['Web']['rs_header'], 'r');
                        while (false != ($line = fgets($fp, 4096))) {
                            if (stripos($line, "Content-Type") !== false)
                                $ct = $line;
                            if (stripos($line, "Content-Encoding:") !== false)
                                $ce = $line;
                            if (stripos($line, "Location:") !== false)
                                $lo = $line;
                        }
                        fclose($fp);
                        if (!empty($lo)) {
                            // se il proxy e' attivo allora redireziono altrimenti no
                            $uri = $_SERVER['REQUEST_URI'];
                            $i = stripos($uri, "http://");
                            if ($i !== false)
                                header($lo);
                        }
                        if (!empty($ct))
                            header($ct);
                        if (!empty($ce)) {
                            //$ce = "Content-Encoding:gzip";
                            header($ce);
                        }
                        
                        header("Content-Length: " . filesize($web['Web']['rs_body']));
                        readfile($web['Web']['rs_body']);
                    }
                    
                    exit();
                }
        }

        function pcap($id = null) {
                if (!$id) {
                    exit();
                }
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                $this->Web->recursive = -1;
                $web = $this->Web->read(null, $id);
                if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                    $this->redirect('/users/login');
                }
                else {
                    $file_pcap = "/tmp/http_".time()."_".$id.".pcap";
                    $this->Xml2Pcap->doPcap($file_pcap, $web['Web']['flow_info']);
                    $this->autoRender = false;
                    header("Content-Disposition: filename=http_".$id.".pcap");
                    header("Content-Type: binary");
                    header("Content-Length: " . filesize($file_pcap));
                    @readfile($file_pcap);
                    unlink($file_pcap);
                    exit();
                }
        }

        function hijacking($id = null) {
            if (!$id) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Web->recursive = -1;
            $web = $this->Web->read(null, $id);
            if ($polid != $web['Web']['pol_id'] || $solid != $web['Web']['sol_id']) {
                //$this->redirect('/users/login');
            }
            if (file_exists($web['Web']['rq_header'])) {
                $this->layout = 'cookies';
                $file_h = file($web['Web']['rq_header']);
                $cookie = array();
                foreach ($file_h as $line) {
                    $cpos = strpos($line, 'Cookie: ');
                    if ($cpos !== false && $cpos == 0) {
                        $cookies = str_replace('Cookie: ', '', $line);
                        $cookies = str_replace("\r\n", '', $cookies);
                        $cookies = str_replace("; ", ';', $cookies);
                        $cookie = explode(";", $cookies);
                    }
                    $host = strpos($line, 'Host: ');
                    if ($host !== false) {
                        $dpos = strpos($line, '.');
                        $host = substr($line, $dpos+1);
                        $host = str_replace("\r\n", '', $host);
                        $this->set('domain', $host);
                    }
                    
                }
                $this->set('url', $web['Web']['url']);
                $this->set('cookies', $cookie);
            }
        }
}
?>
