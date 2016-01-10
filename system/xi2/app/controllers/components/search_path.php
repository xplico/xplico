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

/* import all models */
App::import('Model', 'Web');
App::import('Model', 'Fbchat');
App::import('Model', 'Ftp');
App::import('Model', 'Ftp_file');
App::import('Model', 'Tftp');
App::import('Model', 'Tftp_file');
App::import('Model', 'Pjl');
App::import('Model', 'Email');
App::import('Model', 'Mmscontent');
App::import('Model', 'Feed_xml');
App::import('Model', 'Nntp_article');
App::import('Model', 'Telnet');
App::import('Model', 'Sip');
App::import('Model', 'Webmail');
App::import('Model', 'Httpfile');
App::import('Model', 'Unknow');
App::import('Model', 'Rtp');
App::import('Model', 'Irc');
App::import('Model', 'Irc_channel');
App::import('Model', 'Paltalk_exp');
App::import('Model', 'Paltalk_room');
App::import('Model', 'Msn_chat');



class SearchPathComponent extends Object
{
    var $controller = true;
    var $Session;

    function startup(&$controller) {
        // This method takes a reference to the controller which is loading it.
        // Perform controller initialization here.
        $this->Session = $controller->Session;
    }
    
    function ItemPage($path) {
        /* find pol, sol and the type of item */
        list($pol_id, $sol_id, $rest) = sscanf($path, "/opt/xplico/pol_%d/sol_%d/%s");
        $type = strtok($rest, '/');

        /* set sol id and pol id to avoid error permision in the controller */
        $this->Session->write('pol', $pol_id);
        $this->Session->write('sol', $sol_id);
        
        /* controller and id */
        $control = null;
        $id = null;
        switch ($type) {
        case 'http':
            /* load model */
            $Feed = new Feed_xml();
            /* find id */
            $control = 'feeds';
            $conditions = array('Feed_xml.rs_body' => $path);
            $param = array('recursive' => 0, 'fields' => array('Feed_xml.id'),  'conditions' => $conditions);
            $id = $Feed->find('first', $param);
            if ($id != null) {
                $redir = '/'.$control.'/xml/'.$id['Feed_xml']['id'];
            }
            else {
                /* load model */
                $Web = new Web();
                /* find id */
                $control = 'webs';
                $conditions = array( "or" => array('Web.rq_header' => $path, 'Web.rs_header' => $path, 'Web.rq_body' => $path, 'Web.rs_body' => $path));
                $param = array('recursive' => 0, 'fields' => array('Web.id'),  'conditions' => $conditions);
                $id = $Web->find('first', $param);
                if ($id != null) {
                    $redir = '/'.$control.'/resBody/'.$id['Web']['id'];
                }
            }
            break;
            
        case 'fbwchat':
            /* load model */
            $Fbc = new Fbchat();
            /* find id */
            $control = 'fbuchats';
            $conditions = array('Fbchat.chat' => $path);
            $param = array('recursive' => 0, 'fields' => array('Fbchat.id'),  'conditions' => $conditions);
            $id = $Fbc->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Fbchat']['id'];
            break;

        case 'ftp':
            /* load model */
            $Ftp = new Ftp_file();
            /* find id */
            $control = 'ftps';
            $conditions = array('Ftp_file.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Ftp_file.id'),  'conditions' => $conditions);
            $id = $Ftp->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Ftp_file']['id'];
            else {
                /* load model */
                $Ftp = new Ftp();
                /* find id */
                $control = 'ftps';
                $conditions = array('Ftp.cmd_path' => $path);
                $param = array('recursive' => 0, 'fields' => array('Ftp.id'),  'conditions' => $conditions);
                $id = $Ftp->find('first', $param);
                if ($id != null)
                    $redir = '/'.$control.'/view/'.$id['Ftp']['id'];
            }
            break;

        case 'ipp':
        case 'pjl':
            /* load model */
            $Pjl = new Pjl();
            /* find id */
            $control = 'pjls';
            $conditions = array( "or" => array('Pjl.pcl_path' => $path, 'Pjl.pdf_path' => $path));
            $param = array('recursive' => 0, 'fields' => array('Pjl.id'),  'conditions' => $conditions);
            $id = $Pjl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Pjl']['id'];
            break;

        case 'mail':
            /* load model */
            $Mail = new Email();
            /* find id */
            $control = 'emails';
            $conditions = array('Email.mime_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Email.id'),  'conditions' => $conditions);
            $id = $Mail->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Email']['id'];
            break;
            
        case 'mms':
            /* load model */
            $Mms = new Mmscontent();
            /* find id */
            $control = 'mms';
            $conditions = array('Mmscontent.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Mmscontent.id'),  'conditions' => $conditions);
            $id = $Mms->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Mmscontent']['id'];
            break;
            
        case 'nntp':
            /* load model */
            $Nntp = new Nntp_article();
            /* find id */
            $control = 'nntp_groups';
            $conditions = array('Nntp_article.mime_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Nntp_article.id'),  'conditions' => $conditions);
            $id = $Nntp->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Nntp_article']['id'];
            break;

        case 'telnet':
            /* load model */
            $Teln = new Telnet();
            /* find id */
            $control = 'telnets';
            $conditions = array('Telnet.cmd' => $path);
            $param = array('recursive' => 0, 'fields' => array('Telnet.id'),  'conditions' => $conditions);
            $id = $Teln->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Telnet']['id'];
            
            break;

        case 'tftp':
            /* load model */
            $Tftp = new Tftp_file();
            $control = 'tftps';
            $conditions = array('Tftp_file.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Tftp_file.id'),  'conditions' => $conditions);
            $id = $Tftp->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Tftp_file']['id'];
            else {
                /* load model */
                $Tftp = new Tftp();
                /* find id */
                $control = 'tftps';
                $conditions = array('Tftp.cmd_path' => $path);
                $param = array('recursive' => 0, 'fields' => array('Tftp.id'),  'conditions' => $conditions);
                $id = $Tftp->find('first', $param);
                if ($id != null)
                    $redir = '/'.$control.'/view/'.$id['Tftp']['id'];
            }
            break;
        
        case 'sip':
            /* load model */
            $mdl = new Sip();
            $control = 'sips';
            $conditions = array('Sip.commands' => $path);
            $param = array('recursive' => 0, 'fields' => array('Sip.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Sip']['id'];
            else {
                $conditions = array('Sip.ucaller' => $path);
                $param = array('recursive' => 0, 'fields' => array('Sip.id'),  'conditions' => $conditions);
                $id = $mdl->find('first', $param);
                if ($id != null)
                    $redir = '/'.$control.'/view/'.$id['Sip']['id'];
                else {
                    $conditions = array('Sip.ucalled' => $path);
                    $param = array('recursive' => 0, 'fields' => array('Sip.id'),  'conditions' => $conditions);
                    $id = $mdl->find('first', $param);
                    if ($id != null)
                        $redir = '/'.$control.'/view/'.$id['Sip']['id'];
                }
            }
            break;
        
        case 'webmail':
            /* load model */
            $mdl = new Webmail();
            $control = 'webmails';
            $conditions = array('Webmail.mime_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Webmail.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Webmail']['id'];
            break;
        
        case 'httpfile':
            /* load model */
            $mdl = new Httpfile();
            $control = 'httpfile';
            $conditions = array('Httpfile.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Httpfile.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Httpfile']['id'];
            break;

        case 'grbudp':
            /* load model */
            $mdl = new Unknow();
            $control = 'unknows';
            $conditions = array('Unknow.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Unknow']['id'];
            break;

        case 'grbtcp':
            /* load model */
            $mdl = new Unknow();
            $control = 'unknows';
            $conditions = array('Unknow.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Unknow']['id'];
            break;

        case 'rtp':
            /* load model */
            $mdl = new Rtp();
            $control = 'rtps';
            $conditions = array('Rtp.ucaller' => $path);
            $param = array('recursive' => 0, 'fields' => array('Rtp.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Rtp']['id'];
            else {
                $conditions = array('Rtp.ucalled' => $path);
                $param = array('recursive' => 0, 'fields' => array('Rtp.id'),  'conditions' => $conditions);
                $id = $mdl->find('first', $param);
                if ($id != null)
                    $redir = '/'.$control.'/view/'.$id['Rtp']['id'];
            }
            break;

        case 'irc':
            /* load model */
            $mdl = new Irc();
            $control = 'ircs';
            $conditions = array('Irc.cmd_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Irc.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Irc']['id'];
            else {
                /* load model */
                $mdl = new Irc_channel();
                $control = 'ircs';
                $conditions = array('Irc_channel.channel_path' => $path);
                $param = array('recursive' => 0, 'fields' => array('Irc_channel.id'),  'conditions' => $conditions);
                $id = $mdl->find('first', $param);
                if ($id != null)
                    $redir = '/'.$control.'/channel/'.$id['Irc_channel']['id'];
            }
            break;

        case 'paltalk_exp':
            /* load model */
            $mdl = new Paltalk_exp();
            $control = 'paltalk_exps';
            $conditions = array('Paltalk_exp.channel_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Paltalk_exp.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Paltalk_exp']['id'];
            break;

        case 'paltalk':
            /* load model */
            $mdl = new Paltalk_room();
            $control = 'paltalk_rooms';
            $conditions = array('Paltalk_room.room_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Paltalk_room.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Paltalk_room']['id'];
            break;

        case 'msn':
            /* load model */
            $mdl = new Msn_chat();
            $control = 'msn_chats';
            $conditions = array('Msn_chat.chat_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Msn_chat.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id != null)
                $redir = '/'.$control.'/view/'.$id['Msn_chat']['id'];
            break;
        }


        if ($id != null)
            return $redir;
        
        return null;
    }


    function ItemModelId($path) {
        /* find pol, sol and the type of item */
        list($pol_id, $sol_id, $rest) = sscanf($path, "/opt/xplico/pol_%d/sol_%d/%s");
        $type = strtok($rest, '/');

        /* set sol id and pol id to avoid error permision in the controller */
        $this->Session->write('pol', $pol_id);
        $this->Session->write('sol', $sol_id);
        
        /* controller and id */
        $control = null;
        $id = null;
        switch ($type) {
        case 'http':
            /* load model */
            $Feed = new Feed_xml();
            /* find id */
            $control = 'Feed_xml';
            $conditions = array('Feed_xml.rs_body' => $path);
            $param = array('recursive' => 0, 'fields' => array('Feed_xml.id'),  'conditions' => $conditions);
            $id = $Feed->find('first', $param);
            if ($id == null) {
                /* load model */
                $Web = new Web();
                /* find id */
                $control = 'Web';
                $conditions = array( "or" => array('Web.rq_header' => $path, 'Web.rs_header' => $path, 'Web.rq_body' => $path, 'Web.rs_body' => $path));
                $param = array('recursive' => 0, 'fields' => array('Web.id'),  'conditions' => $conditions);
                $id = $Web->find('first', $param);
            }
            break;
            
        case 'fbwchat':
            /* load model */
            $Fbc = new Fbchat();
            /* find id */
            $control = 'Fbchat';
            $conditions = array('Fbchat.chat' => $path);
            $param = array('recursive' => 0, 'fields' => array('Fbchat.id'),  'conditions' => $conditions);
            $id = $Fbc->find('first', $param);
            break;

        case 'ftp':
            /* load model */
            $Ftp = new Ftp_file();
            /* find id */
            $control = 'Ftp_file';
            $conditions = array('Ftp_file.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Ftp_file.id'),  'conditions' => $conditions);
            $id = $Ftp->find('first', $param);
            if ($id == null) {
                /* load model */
                $Ftp = new Ftp();
                /* find id */
                $control = 'Ftp';
                $conditions = array('Ftp.cmd_path' => $path);
                $param = array('recursive' => 0, 'fields' => array('Ftp.id'),  'conditions' => $conditions);
                $id = $Ftp->find('first', $param);
            }
            break;

        case 'ipp':
        case 'pjl':
            /* load model */
            $Pjl = new Pjl();
            /* find id */
            $control = 'Pjl';
            $conditions = array( "or" => array('Pjl.pcl_path' => $path, 'Pjl.pdf_path' => $path));
            $param = array('recursive' => 0, 'fields' => array('Pjl.id'),  'conditions' => $conditions);
            $id = $Pjl->find('first', $param);
            break;

        case 'mail':
            /* load model */
            $Mail = new Email();
            /* find id */
            $control = 'Email';
            $conditions = array('Email.mime_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Email.id'),  'conditions' => $conditions);
            $id = $Mail->find('first', $param);
            break;
            
        case 'mms':
            /* load model */
            $Mms = new Mmscontent();
            /* find id */
            $control = 'Mmscontent';
            $conditions = array('Mmscontent.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Mmscontent.id'),  'conditions' => $conditions);
            $id = $Mms->find('first', $param);
            break;
            
        case 'nntp':
            /* load model */
            $Nntp = new Nntp_article();
            /* find id */
            $control = 'Nntp_article';
            $conditions = array('Nntp_article.mime_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Nntp_article.id'),  'conditions' => $conditions);
            $id = $Nntp->find('first', $param);
            break;

        case 'telnet':
            /* load model */
            $Teln = new Telnet();
            /* find id */
            $control = 'Telnet';
            $conditions = array('Telnet.cmd' => $path);
            $param = array('recursive' => 0, 'fields' => array('Telnet.id'),  'conditions' => $conditions);
            $id = $Teln->find('first', $param);
            break;

        case 'tftp':
            /* load model */
            $Tftp = new Tftp_file();
            $control = 'Tftp_file';
            $conditions = array('Tftp_file.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Tftp_file.id'),  'conditions' => $conditions);
            $id = $Tftp->find('first', $param);
            if ($id == null) {
                /* load model */
                $Tftp = new Tftp();
                /* find id */
                $control = 'Tftp';
                $conditions = array('Tftp.cmd_path' => $path);
                $param = array('recursive' => 0, 'fields' => array('Tftp.id'),  'conditions' => $conditions);
                $id = $Tftp->find('first', $param);
            }
            break;
        
        case 'sip':
            /* load model */
            $mdl = new Sip();
            $control = 'sips';
            $conditions = array('Sip.commands' => $path);
            $param = array('recursive' => 0, 'fields' => array('Sip.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id == null) {
                $conditions = array('Sip.ucaller' => $path);
                $param = array('recursive' => 0, 'fields' => array('Sip.id'),  'conditions' => $conditions);
                $id = $mdl->find('first', $param);
                if ($id == null) {
                    $conditions = array('Sip.ucalled' => $path);
                    $param = array('recursive' => 0, 'fields' => array('Sip.id'),  'conditions' => $conditions);
                    $id = $mdl->find('first', $param);
                }
            }
            break;
        
        case 'webmail':
            /* load model */
            $mdl = new Webmail();
            $control = 'webmails';
            $conditions = array('Webmail.mime_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Webmail.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            break;
        
        case 'httpfile':
            /* load model */
            $mdl = new Httpfile();
            $control = 'httpfile';
            $conditions = array('Httpfile.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Httpfile.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            break;

        case 'grbudp':
            /* load model */
            $mdl = new Unknow();
            $control = 'unknows';
            $conditions = array('Unknow.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            break;

        case 'grbtcp':
            /* load model */
            $mdl = new Unknow();
            $control = 'unknows';
            $conditions = array('Unknow.file_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            break;

        case 'rtp':
            /* load model */
            $mdl = new Rtp();
            $control = 'rtps';
            $conditions = array('Rtp.ucaller' => $path);
            $param = array('recursive' => 0, 'fields' => array('Rtp.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id == null) {
                $conditions = array('Rtp.ucalled' => $path);
                $param = array('recursive' => 0, 'fields' => array('Rtp.id'),  'conditions' => $conditions);
                $id = $mdl->find('first', $param);
            }
            break;

        case 'irc':
            /* load model */
            $mdl = new Irc();
            $control = 'ircs';
            $conditions = array('Irc.cmd_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Irc.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            if ($id == null) {
                /* load model */
                $mdl = new Irc_channel();
                $control = 'ircs';
                $conditions = array('Irc_channel.channel_path' => $path);
                $param = array('recursive' => 0, 'fields' => array('Irc_channel.id'),  'conditions' => $conditions);
                $id = $mdl->find('first', $param);
            }
            break;

        case 'paltalk_exp':
            /* load model */
            $mdl = new Paltalk_exp();
            $control = 'paltalk_exps';
            $conditions = array('Paltalk_exp.channel_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Paltalk_exp.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            break;

        case 'paltalk':
            /* load model */
            $mdl = new Paltalk_room();
            $control = 'paltalk_rooms';
            $conditions = array('Paltalk_room.room_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Paltalk_room.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            break;

        case 'msn':
            /* load model */
            $mdl = new Msn_chat();
            $control = 'msn_chats';
            $conditions = array('Msn_chat.chat_path' => $path);
            $param = array('recursive' => 0, 'fields' => array('Msn_chat.id'),  'conditions' => $conditions);
            $id = $mdl->find('first', $param);
            break;


        }
        
        if ($id != null)
            return array('model' => $control, 'id' => $id[$control]['id']);
        
        return null;
    }
}
?>
