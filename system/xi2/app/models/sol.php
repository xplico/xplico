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

  class Sol extends AppModel
  {
    var $name = 'Sol';

    var $validate = array(
        'name' => '/^.{1,200}$/'
        );

    var $belongsTo = array( 'Pol' =>
                            array(
                                'className' => 'Pol'
                                )
        );

    var $hasMany = array( 'Source' =>
                          array(
                              'className' => 'Source',
                              'dependent' => true
                              ),
                          'Email' =>
                          array(
                              'className' => 'Email',
                              'dependent' => true
                              ),
                          'Input' =>
                          array(
                              'className' => 'Input',
                              'dependent' => true
                              ),
                          'Web' =>
                          array(
                              'className' => 'Web',
                              'dependent' => true
                              ),
                          'Sip' =>
                          array(
                              'className' => 'Sip',
                              'dependent' => true
                              ),
                          'Ftp' =>
                          array(
                              'className' => 'Ftp',
                              'dependent' => true
                              ),
                          'Ftp_file' =>
                          array(
                              'className' => 'Ftp_file',
                              'dependent' => true
                              ),
                          'Pjl' =>
                          array(
                              'className' => 'Pjl',
                              'dependent' => true
                              ),
                          'Mm' =>
                          array(
                              'className' => 'Mm',
                              'dependent' => true
                              ),
                          'Mmscontent' =>
                          array(
                              'className' => 'Mmscontent',
                              'dependent' => true
                              ),
                          'Feed' =>
                          array(
                              'className' => 'Feed',
                              'dependent' => true
                              ),
                          'Feed_xml' =>
                          array(
                              'className' => 'Feed_xml',
                              'dependent' => true
                              ),
                          'Tftp' =>
                          array(
                              'className' => 'Tftp',
                              'dependent' => true
                              ),
                          'Tftp_file' =>
                          array(
                              'className' => 'Tftp_file',
                              'dependent' => true
                              ),
                          'DnsMessage' =>
                          array(
                              'className' => 'DnsMessage',
                              'dependent' => true
                              ),
                          'Fbchat' =>
                          array(
                              'className' => 'Fbchat',
                              'dependent' => true
                              ),
                          'Fbuchat' =>
                          array(
                              'className' => 'Fbuchat',
                              'dependent' => true
                              ),
                          'Telnet' =>
                          array(
                              'className' => 'Telnet',
                              'dependent' => true
                              ),
                          'Webmail' =>
                          array(
                              'className' => 'Webmail',
                              'dependent' => true
                              ),
                          'Httpfile' =>
                          array(
                              'className' => 'Httpfile',
                              'dependent' => true
                              ),
                          'Unknow' =>
                          array(
                              'className' => 'Unknow',
                              'dependent' => true
                              ),
                          'Rtp' =>
                          array(
                              'className' => 'Rtp',
                              'dependent' => true
                              ),
                          'Arp' =>
                          array(
                              'className' => 'Arp',
                              'dependent' => true
                              ),
                          'Irc' =>
                          array(
                              'className' => 'Irc',
                              'dependent' => true
                              ),
                          'Irc_channel' =>
                          array(
                              'className' => 'Irc_channel',
                              'dependent' => true
                              ),
                          'Paltalk_exp' =>
                          array(
                              'className' => 'Paltalk_exp',
                              'dependent' => true
                              ),
                          'Paltalk_room' =>
                          array(
                              'className' => 'Paltalk_room',
                              'dependent' => true
                              ),
                          'Msn_chat' =>
                          array(
                              'className' => 'Msn_chat',
                              'dependent' => true
                              ),
                          'Icmpv6' =>
                          array(
                              'className' => 'Icmpv6',
                              'dependent' => true
                              ),
                          'Mgcp' =>
                          array(
                              'className' => 'Mgcp',
                              'dependent' => true
                              ),
                          'Webymsg' =>
                          array(
                              'className' => 'Webymsg',
                              'dependent' => true
                              ),
                          'Syslog' =>
                          array(
                              'className' => 'Syslog',
                              'dependent' => true
                              ),
                          'Unkfile' =>
                          array(
                              'className' => 'Unkfile',
                              'dependent' => true
                              ),
                          'Whatsapp' =>
                          array(
                              'className' => 'Whatsapp',
                              'dependent' => true
                              )
        );
  }
?>
