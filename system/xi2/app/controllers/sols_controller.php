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

uses ('sanitize');

class SolsController extends AppController {
    var $name = 'Sols';
    var $helpers = array('Html', 'Form', 'Javascript');
    var $components = array('Xplico');
    var $uses = array('Sol', 'Pol', 'User', 'Source', 'Email', 'Web', 'Ftp', 'Ftp_file', 'Sip', 'Mm', 'Mmscontent',
                      'Pjl', 'Feed', 'Tftp', 'Tftp_file', 'DnsMessage', 'Nntp_group', 'Nntp_article', 'Fbuchat',
                      'Fbchat', 'Telnet', 'Webmail', 'Httpfile', 'Unknow', 'Rtp', 'Arp', 'Irc', 'Irc_channel',
                      'Paltalk_exp', 'Paltalk_room', 'Msn_chat', 'Icmpv6', 'Syslog', 'Unkfile', 'Webymsg', 'Mgcp',
                      'Whatsapp');
    var $pcap_limit = 10485760;
    
    function beforeFilter() {
        $groupid = $this->Session->read('group');
        $polid = $this->Session->read('pol');
        if (!$groupid || !$polid) {
            $this->Session->delete('sol');
            $this->Session->delete('host_id');
            $this->redirect('/users/login');
        }
    }

    private function get_dir_size($dir_name){
        $dir_size =0;
        if (is_dir($dir_name)) {
            if ($dh = opendir($dir_name)) {
                while (($file = readdir($dh)) !== false) {
                    if($file !='.' && $file != '..'){
                        if(is_file($dir_name.'/'.$file)){
                            $dir_size += filesize($dir_name.'/'.$file);
                        }
                        /* check for any new directory inside this directory */
                        if(is_dir($dir_name.'/'.$file)){
                            $dir_size +=  get_dir_size($dir_name.'/'.$file);
                        }
                    }
                }
            }
        }
        closedir($dh);
        return $dir_size;
    }

    
    function index() {
        $polid = $this->Session->read('pol');
        $this->Session->delete('host_id');
        $this->Sol->recursive = -1;
        $this->Pol->recursive = -1;
        $pol_data = $this->Pol->read(null, $polid);
        $sols = $this->Sol->find('all', array('conditions' => "pol_id = $polid", 'order' => 'Sol.id DESC'));
        $this->set('pol_name', $pol_data['Pol']['name']);
        $this->set('sols', $sols);
        if ($this->Session->check('admin')) {
            // admin menu
            $this->set('menu_left',
                   array('active' => '0', 'sections' => array(
                             array('name' => __('Case', true), 'sub' => array(
                                       array('name' => __('Cases', true), 'link' => '/pols'),
                                       array('name' => __('Sessions', true), 'link' => '/sols/index')
                                       )
                                 )
                             )
                       )
            );
        }
        else {
            // normal user menu
            $this->set('menu_left',
                   array('active' => '0', 'sections' => array(
                             array('name' => __('Case', true), 'sub' => array(
                                       array('name' => __('Cases', true), 'link' => '/pols'),
                                       array('name' => __('Sessions', true), 'link' => '/sols/index'),
                                       array('name' => __('New Session', true), 'link' => '/sols/add')
                                       )
                                 )
                             )
                       )
            );
        }
        if (!empty($sols['0']['Sol']['id']))
            $this->Session->write('last_sol_id', $sols['0']['Sol']['id']);
    }

    function view($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for Session.', true));
            $this->redirect('/sols/index');
        }
        $pbar = false;
        $this->Session->delete('interface');
        $this->Sol->recursive = 0;
        $sol = $this->Sol->read(null, $id);
        if ($sol['Sol']['pol_id'] == $this->Session->read('pol')) {
            $this->Session->write('sol', $id);
            $live = $sol['Pol']['realtime'];
            $this->set('live', $live);
            if ($live) {
                $pol = $this->Session->read('pol');
                $start_file = '/opt/xplico/pol_'.$pol.'/realtime_start';
                if (file_exists($start_file)) {
                    $this->set('livestop', 1);
                    /* SEND THE INTERFACE IN USE TO THE VIEW AND DISPLAY IT */
                    $this->set('interff', $this->Session->read('interfaceInUse'));
                }
                else {
                    $interface = array();
                    $foca = popen('ifconfig | grep flags | awk -F: \'{print $1;}\'', 'r');
                    if ($foca) {
                        while (!feof($foca)) {
                            $buffer = trim(fgets($foca, 200));
                            if ($buffer != '') {
                                        $interface[] = $buffer;
                            }
                        }
                        pclose($foca);
                    }
                    $this->set('interface', $interface);
                    $this->Session->write('interface', $interface);
                    $this->set('livestop', 0);
                }
            }


            // hosts list
            $this->Source->recursive = -1;
            $conditions = array(
                'conditions' => array('Source.sol_id' => $id),
                'order'      => 'ip ASC',
                'limit'      => null,
                'fields'     => array(str_replace('{n}.','', "{n}.Source.id"), str_replace('{n}.','',"{n}.Source.ip"))    );
            $this->set('hosts',  $this->Source->find("list", $conditions));


            // selected host
            $host_id   = $this->Session->read('host_id');
            $host_srch = "";
            if (!empty($host_id['host']) && $host_id != 0) {
                $host_srch = " AND source_id = ".$host_id['host'];
                $this->set('host', $host_id['host']);
            }
            else {
                $this->set('host', 0);
            }


            // web number
            $this->Web->recursive = -1;

            $web_post  = $this->Web->find('count', array('conditions' => ("sol_id = $id AND method = 'POST'".$host_srch)));
            $web_get   = $this->Web->find('count', array('conditions' => ("sol_id = $id AND method = 'GET'".$host_srch)));
            $web_video = $this->Web->find('count', array('conditions' => ("sol_id = $id AND content_type LIKE '%video%'".$host_srch )));
            $web_image = $this->Web->find('count', array('conditions' => ("sol_id = $id AND content_type LIKE '%image%'".$host_srch )));

            $this->set('web_post',  $web_post);
            $this->set('web_get',   $web_get);
            $this->set('web_video', $web_video);
            $this->set('web_image', $web_image);

            // email number
            $this->Email->recursive = -1;
            $eml_received = $this->Email->find('count', array('conditions' => ("sol_id = $id AND receive = TRUE".$host_srch)));
            if ($eml_received == '') {
                $eml_received = $this->Email->find('count', array('conditions' => ("sol_id = $id AND receive = 1".$host_srch)));
            }
            $eml_total = $this->Email->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $eml_sended = $eml_total - $eml_received;
            $eml_unread =  $eml_total - $this->Email->find('count', array('conditions' => ("sol_id = $id AND first_visualization_user_id != 0".$host_srch)));
            $this->set('eml_received', $eml_received);
            $this->set('eml_sended',   $eml_sended);
            $this->set('eml_unread',   $eml_unread);
            $this->set('eml_total',    $eml_total);

            // ftp number
            $this->Ftp->recursive = -1;
            $this->Ftp_file->recursive = -1;
            $ftp_num  = $this->Ftp->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $ftp_down = $this->Ftp_file->find('count', array('conditions' => ("sol_id = $id AND dowloaded = 1".$host_srch)));
            $ftp_up   = $this->Ftp_file->find('count', array('conditions' => ("sol_id = $id".$host_srch))) - $ftp_down;
            $this->set('ftp_num',  $ftp_num);
            $this->set('ftp_down', $ftp_down);
            $this->set('ftp_up',   $ftp_up);
            // mms number
            $this->Mm->recursive = -1;
            $this->Mmscontent->recursive = -1;
            $mms_num   = $this->Mm->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $mms_cont  = $this->Mmscontent->find('count', array('conditions' => ("sol_id = $id".$host_srch))) - $mms_num;
            $mms_video = $this->Mmscontent->find('count', array('conditions' => ("sol_id = $id AND content_type LIKE '%video%'".$host_srch)));
            $mms_image = $this->Mmscontent->find('count', array('conditions' => ("sol_id = $id AND content_type LIKE '%image%'".$host_srch)));
            $this->set('mms_num',   $mms_num);
            $this->set('mms_cont',  $mms_cont);
            $this->set('mms_video', $mms_video);
            $this->set('mms_image', $mms_image);
            // pjl number
            $this->Pjl->recursive = -1;
            $pjl_num = $this->Pjl->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('pjl_num', $pjl_num);
            // feed number
            $this->Feed->recursive = -1;
            $feed_num = $this->Feed->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('feed_num', $feed_num);
            // tftp number
            $this->Tftp->recursive = -1;
            $this->Tftp_file->recursive = -1;
            $tftp_num = $this->Tftp->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $tftp_down = $this->Tftp_file->find('count', array('conditions' => ("sol_id = $id AND dowloaded = 1".$host_srch)));
            $tftp_up = $this->Tftp_file->find('count', array('conditions' => ("sol_id = $id".$host_srch))) - $tftp_down;
            $this->set('tftp_num', $tftp_num);
            $this->set('tftp_down', $tftp_down);
            $this->set('tftp_up', $tftp_up);
            // sip number
            $this->Sip->recursive = -1;
            $sip_calls = $this->Sip->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('sip_calls', $sip_calls);
            // rtp number
            $this->set('rtp_video', 0);
            $this->Rtp->recursive = -1;
            $rtp_audio = $this->Rtp->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('rtp_audio', $rtp_audio);
            // dns number
            $this->DnsMessage->recursive = -1;
            $dns_num = $this->DnsMessage->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('dns_num', $dns_num);
            // nntp number
            $this->Nntp_group->recursive = -1;
            $nntp_grp = $this->Nntp_group->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('nntp_grp', $nntp_grp);
            $this->Nntp_article->recursive = -1;
            $nntp_artcl = $this->Nntp_article->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('nntp_artcl', $nntp_artcl);
            // facebook chat number
            $this->Fbuchat->recursive = -1;
            $fbc_users = $this->Fbuchat->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('fbc_users', $fbc_users);
            $this->Fbchat->recursive = -1;
            $fbc_chats = $this->Fbchat->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('fbc_chats', $fbc_chats);
            // telnet number
            $this->Telnet->recursive = -1;
            $telnet_num = $this->Telnet->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('telnet_num', $telnet_num);
            // webmail
            $this->Webmail->recursive = -1;
            $webmail_num = $this->Webmail->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $webmail_received =  $this->Webmail->find('count', array('conditions' => ("sol_id = $id AND Webmail.receive = TRUE".$host_srch)));
            if ($webmail_received == '') {
                $webmail_received =  $this->Webmail->find('count', array('conditions' => ("sol_id = $id AND Webmail.receive = 1".$host_srch)));
            }
            $this->set('webmail_num', $webmail_num);
            $this->set('webmail_receiv', $webmail_received);
            $this->set('webmail_sent', $webmail_num - $webmail_received);
            // httpfile number
            $this->Httpfile->recursive = -1;
            $httpfile_num = $this->Httpfile->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('httpfile_num', $httpfile_num);
            // unknow number
            $this->Unknow->recursive = -1;
            $text_num = $this->Unknow->find('count', array('conditions' => ("sol_id = $id AND Unknow.file_path != 'None'".$host_srch)));
            $unk_num = $this->Unknow->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('text_num', $text_num.'/'.$unk_num);
            // arp number
            $this->Arp->recursive = -1;
            $arp_num = $this->Arp->find('count', array('conditions' => ("sol_id = $id")));
            $this->set('arp_num', $arp_num);
            // irc number
            $this->Irc->recursive = -1;
            $irc_num = $this->Irc->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('irc_num', $irc_num);
            // irc channels number
            $this->Irc_channel->recursive = -1;
            $irc_chnl_num = $this->Irc_channel->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('irc_chnl_num', $irc_chnl_num);
            // Paltalk Express number
            $this->Paltalk_exp->recursive = -1;
            $paltalk_exp_num = $this->Paltalk_exp->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('paltalk_exp_num', $paltalk_exp_num);
            // Paltalk
            $this->Paltalk_room->recursive = -1;
            $paltalk_num = $this->Paltalk_room->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('paltalk_num', $paltalk_num);
            // msn
            $this->Msn_chat->recursive = -1;
            $msn_num = $this->Msn_chat->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('msn_num', $msn_num);
            // icmpv6 number
            $this->Icmpv6->recursive = -1;
            $icmpv6_num = $this->Icmpv6->find('count', array('conditions' => ("sol_id = $id")));
            $this->set('icmpv6_num', $icmpv6_num);
            // dig
            $this->Unkfile->recursive = -1;
            $dig_num = $this->Unkfile->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('dig_num', $dig_num);
            // syslog number
            $this->Syslog->recursive = -1;
            $syslog_num = $this->Syslog->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('syslog_num', $syslog_num);
            // yahoo msg
            $this->Webymsg->recursive = -1;
            $webymsg = $this->Webymsg->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('webymsg', $webymsg);
            // mgcp number
            $this->Mgcp->recursive = -1;
            $mgcp_calls = $this->Mgcp->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('mgcp_calls', $mgcp_calls);
            // whatsapp number
            $this->Whatsapp->recursive = -1;
            $whatsapp_num = $this->Whatsapp->find('count', array('conditions' => ("sol_id = $id".$host_srch)));
            $this->set('whatsapp_num', $whatsapp_num);
            
            // estimated time
            $fh = @fopen('/opt/xplico/pol_'.$sol['Sol']['pol_id'].'/tmp/elab_status.log', 'r');
            if ($fh) {
                $pbar = true;
                $vlist = fscanf($fh, 's:%d r:%d');
                list($esize, $etime) = $vlist;
                fclose($fh);
                if (!$this->Session->check('start_tm')) {
                    $start_tm = time();
                    $this->Session->write('start_tm', $start_tm);
                }
                else {
                    $start_tm = $this->Session->read('start_tm');
                }
                if ($etime == 0) {
                    if ($this->Session->check('etime')) {
                        $etime = $this->Session->read('etime');
                        $esize = $this->Session->read('esize');
                    }
                }
                else {
                    $this->Session->write('etime', $etime);
                    $this->Session->write('esize', $esize);
                }
                if ($etime == 0) {
                    $est_time_perc = 0;
                    $est_time = '---';
                    
                    $dec_tot = $this->get_dir_size('/opt/xplico/pol_'.$sol['Sol']['pol_id'].'/sol_'.$id.'/decode');
                    if ($dec_tot == 0) {
                        unlink('/opt/xplico/pol_'.$sol['Sol']['pol_id'].'/tmp/elab_status.log');
                        $this->Session->delete('etime');
                        $this->Session->delete('esize');
                        $this->Session->delete('start_tm');
                        $pbar = false;
                    }
                }
                else {
                    $dec_tot = $this->get_dir_size('/opt/xplico/pol_'.$sol['Sol']['pol_id'].'/sol_'.$id.'/decode');
                    if ($dec_tot == 0) {
                        unlink('/opt/xplico/pol_'.$sol['Sol']['pol_id'].'/tmp/elab_status.log');
                        $this->Session->delete('etime');
                        $this->Session->delete('esize');
                        $this->Session->delete('start_tm');
                        $pbar = false;
                        $est_time_perc = 0;
                        $est_time = '---';
                    }
                    else {
                        $est_time = (int)(($dec_tot/$esize * $etime) - $etime);
                        $est_time_perc = ((time() - $start_tm)/(time() - $start_tm + $est_time))*100;
                    }
                }
                $this->set('est_time_perc', $est_time_perc);
                $this->set('est_time', $est_time);
            }
            // menu
            $this->set('pbar', $pbar);
            $last_sol_id = $this->Session->read('last_sol_id');
            if ($last_sol_id == $id && !$this->Session->check('admin')) {
                $this->set('last_sol', 1);
                /* pcap over ip port */
                $pcap_port_file = '/opt/xplico/pol_'.$sol['Sol']['pol_id'].'/tmp/pcap_ip.port';
                if (file_exists($pcap_port_file)) {
                    $pport = file($pcap_port_file);
                    $this->set('pcapip_port', (int)$pport[0]);
                }
            }
            else
                $this->set('last_sol', 0);
            $this->set('sol', $sol);
            $this->set('menu_left', $this->Xplico->leftmenuarray(0) );
            // demo live version
            if ($this->Session->read('register')) {
                $this->set('register', 1);
                $user = $this->User->read(null, $this->Session->read('userid'));
                if ($user['User']['quota_used'] > $this->pcap_limit) {
                    $this->set('last_sol', 0);
                }
                // help
                $help = $this->Session->read('help');
                $this->Session->write('help', 0);
                $this->set('help', $help);
                if (!$help)
                    $this->set('refresh_time', 30);
            }
            else {
                $this->set('register', 0);
                // help
                $this->set('help', 0);
                $this->set('refresh_time', 30);
            }
        }
        else {
            $this->redirect('/pols/index');
        }
    }

    function add() {
        if ($this->Session->check('admin')) {
            $this->Session->setFlash(__('Administrators can not create new Cases or new Sessions!', true));
            $this->redirect('/sols/index');
        }
        $this->set('menu_left', 
                   array('active' => '0', 'sections' => array(
                             array('name' => __('Case', true), 'sub' => array(
                                       array('name' => __('Cases', true), 'link' => '/pols'),
                                       array('name' => __('Sessions', true), 'link' => '/sols/index')
                                           )
                                 )
                             )
                       )
            );
        if (empty($this->data)) {
            $pol = $this->Session->read('pol');
            $start_file = '/opt/xplico/pol_'.$pol.'/realtime_start';
            if (file_exists($start_file)) {
                $this->Session->setFlash(__('Before add a new session stop the live acquisition!', true));
                $this->redirect('/sols/index');
            }
            else {
                $this->render();
            }
        }
        else {
            $polid = $this->Session->read('pol');
            $this->data['Sol']['pol_id'] = $polid;
            if($this->Sol->save(Sanitize::paranoid($this->data))) {
                system('cd /opt/xplico; /opt/xplico/script/session_mng.pyc -s -d '. $polid . ' ' . $this->Sol->getLastInsertId());
                $this->Session->setFlash(__('The Session has been created', true));
                $this->redirect('/sols/index');
            }
            else {
                $this->Session->setFlash(__('Please correct errors below.', true));
            }
        }
    }

    function delete($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for Session', true));
            $this->redirect('/sols/index');
        }
        $this->Sol->recursive = 0;
        $sol = $this->Sol->read(null, $id);
        if ($sol['Sol']['pol_id'] != $this->Session->read('pol')) {
            $this->Session->setFlash(__('Invalid id for Session', true));
            $this->redirect('/sols/index');
        }
        // request deletion to dema
        $sol['Sol']['rm'] = 1;
        $this->Sol->save($sol);
        // delete directory
        $sol_dir = '/opt/xplico/pol_'.$this->Session->read('pol').'/sol_'.$id;
        $sol_rm = '/opt/xplico/pol_'.$this->Session->read('pol').'/sol_rm';
        system('mv '.$sol_dir.'  '.$sol_rm);
        do {
            sleep(1);
        } while(file_exists($sol_rm));
        $this->Session->setFlash(__('Session deleted', true));
        $this->redirect('/sols/index');
    }

    function pcap() {
        if (!empty($this->data) &&
            is_uploaded_file($this->data['Sols']['File']['tmp_name'])) {
            $userid = $this->Session->read('userid');
            if ($this->Session->read('register')) {
                $this->User->recursive = -1;
                $user = $this->User->read(null, $userid);
                $tot = $user['User']['quota_used'] + filesize($this->data['Sols']['File']['tmp_name']);
                if ($tot > $this->pcap_limit) {
                    $this->Session->setFlash(__('Size limit exceeded. See rules.', true));
                    $this->redirect('/sols/view/'.$this->Session->read('sol'));
                    return;
                }
                else {
                    $this->User->set('quota_used', $tot);
                    $this->User->save();
                }
            }
            $filedec = '/opt/xplico/pol_'.$this->Session->read('pol').'/sol_'.$this->Session->read('sol').'/new/'.$this->data['Sols']['File']['name'];
            move_uploaded_file($this->data['Sols']['File']['tmp_name'], $filedec);
            $this->Session->setFlash(__('File uploaded, wait start decoding...', true));
            $this->redirect('/sols/view/'.$this->Session->read('sol'));
        }
        else {
            $this->Session->setFlash(__('Upload failed, please check', true).' <u><a href="http://forum.xplico.org/viewtopic.php?f=3&t=167">'.__('this', true).'</a></u>.');
            $this->redirect('/sols/index');
        }
    }

    function live() {
        $interface = $this->Session->read('interface');
        $this->Session->delete('interface'); /*to-do claro, aquí me hace un delete */
        $sol = $this->Session->read('sol');
        $pol = $this->Session->read('pol');

        if (!empty($this->data)) {
            if ($interface[$this->data['Interface']['Type']] != '') {

                $this->Session->write('interfaceInUse', $interface[$this->data['Interface']['Type']]); 

                $start_file = '/opt/xplico/pol_'.$pol.'/realtime_start';
                mkdir('/opt/xplico/pol_'.$pol.'/', 0777);
                $fp = fopen($start_file, 'w');
                fwrite($fp, $interface[$this->data['Interface']['Type']]."\n");
                fwrite($fp, 'not ((host '.$_SERVER['SERVER_ADDR'].') && (tcp port '.$_SERVER['SERVER_PORT']."))\n");
                fclose($fp);
                // update time
                $sold = $this->Sol->read(null, $sol);
                if ($sold['Sol']['start_time'] == '0000-00-00 00:00:00') {
                    $sold['Sol']['start_time'] = date('Y-m-d H:i:s');
                    $this->Sol->save($sold);
                }
                $this->Session->setFlash(__('Live capture started.', true));
            }
            else {
                $this->Session->setFlash(__('Select an Interface!', true));
            }
            $this->redirect('/sols/view/'.$sol);
        }
        else {
            $this->Session->setFlash(__('Start Failed', true));
            $this->redirect('/sols/index');
        }
    }

    function livestop() {
        $sol = $this->Session->read('sol');
        $pol = $this->Session->read('pol');
        $start_file = '/opt/xplico/pol_'.$pol.'/realtime_start';
        if (file_exists($start_file)) {
            $start_file = '/opt/xplico/pol_'.$pol.'/realtime_stop';
            $fp = fopen($start_file, 'w');
            // wait stop
            while ($fp) {
                fclose($fp);
                sleep(1);
                $fp = fopen($start_file, 'r');
            }
            // update time
            $sold = $this->Sol->read(null, $sol);
            $sold['Sol']['end_time'] = date('Y-m-d H:i:s');
            $this->Sol->save($sold);
            $this->Session->setFlash(__('Live capture stoped.', true));
        }
        $this->redirect('/sols/view/'.$sol);
    }

    function host() {
        $this->Session->write('host_id', $this->data['host']);
        $sol = $this->Session->read('sol');
        $this->redirect('/sols/view/'.$sol);
    }
}
?>
