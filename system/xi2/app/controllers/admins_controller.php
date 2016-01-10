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

uses('sanitize');
class AdminsController extends AppController
{
    var $helpers = array('Html', 'Form', 'Javascript', 'Ajax' );
    var $components = array('RequestHandler', 'Security', 'Xplico');
    var $uses = array('User', 'Group', 'Pol');
    var $paginate = array('limit' => 16, 'order' => array('User.last_login' => 'desc'));

    function beforeFilter() {
        if (!$this->Session->check('admin')) {
            $this->redirect('/users/login');
        }
        // data input
        if (!empty($this->data)) {
            $this->Security->requirePost('adduser');
        }
        $this->Session->delete('pol');
        $this->Session->delete('sol');
        $this->Security->blackHoleCallback='invalid';
        // admin left menu
        $this->set('menu_left', $this->Xplico->adminleftmenu());
    }


    function invalid() {
        header('HTTP/x 400 Bad Request');
        echo('<h1>HTTP: 400 Bad Request</h1>');
        echo('<p>We\'re sorry - there has been a problem processing your request.  Please try submitting the form again.</p>');
        die();
    }

    function users($gid = null) {
        $this->User->recursive = -1;
        $this->Group->recursive = -1;
        if ($gid != null) {
            $grp = $this->Group->read(null, $gid);
            if (empty($grp)) {
                $gid = null;
            }
        }
        if ($gid == null) {
            $filter['User.em_checked'] = true;
            $this->set('users',$this->paginate('User', $filter));
            $this->set('group', __('all groups', true));
        }
        else {
            $filter['User.group_id'] = $gid;
            $this->set('users',$this->paginate('User', $filter));
            $this->set('group', '\''.$grp['Group']['name'].'\' group');
        }
    }

    function groups() {
        $this->Group->recursive = -1;
  	$this->set('groups', $this->Group->find('all', array('order' => 'Group.name DESC')));
    }

    function uadd() {
        $this->set('username_error', __('Username must be between 6 and 40 characters.', true));
        if (!empty($this->data)) {
            $san = new Sanitize();
            $this->data['User']['username'] = $san->paranoid($this->data['User']['username']);
            $this->data['User']['email'] = $san->paranoid($this->data['User']['email'],
                                                               array('@', '.', '-', '+'));
            
            $this->data['User']['first_name'] = $san->paranoid($this->data['User']['first_name'],
                                                               array('\'', ' '));
            
            $this->data['User']['last_name'] = $san->paranoid($this->data['User']['last_name'],
                                                               array('\'', ' '));
            $this->User->set($this->data);
            if ($this->User->validates()) {
                if ($this->User->findByUsername($this->data['User']['username'])) {
                    $this->User->invalidate('username');
                    $this->set('username_error', __('User already exists.', true));
                }
                else {
                    if ($this->User->findByEmail($this->data['User']['email'])) {
                        $this->User->invalidate('email');
                    }
                    else {
                        $this->data['User']['password'] = md5($this->data['User']['password']);
                        $this->data['User']['group_id'] = $this->data['Admin']['group_id'];
                        $this->data['User']['em_key'] = 'none'; // to www.iSerm.com demo use
                        $this->User->create();
                        if ($this->User->save($this->data)) {
                            $this->Session->setFlash(__('User added', true));
                            $this->User->saveField('em_checked', 1);
                        }
                        $this->redirect('/admins/users');
                    }
                }
            }
            else {
                $this->validateErrors($this->User);
            }
        }
        $groups = $this->Group->find('list');
        $this->set(compact('groups'));
    }


    function gadd($data = null) {
        $this->set('name_error', '');
        if (!empty($this->data)) {
            $san = new Sanitize();
            $this->data['Group']['name'] = $san->paranoid($this->data['Group']['name']);
            $this->Group->set($this->data);
            if ($this->Group->validates()) {
                if ($this->Group->findByName($this->data['Group']['name'])) {
                    $this->Group->invalidate('name');
                    $this->set('name_error', __('Group already exists.', true));
                }
                else {
                    $this->Group->create();
                    if ($this->Group->save($this->data)) {
                        $this->Session->setFlash(__('New Group activated', true));
                        $this->redirect('/admins/groups');
                    }
                    else {
                        $this->Session->setFlash(__('There was a problem creating the new group', true));
                    }
                }
            }
            else {
                $this->validateErrors($this->Group);
            }
        }
    }
    
    function udelete($uid = null) {
        $this->User->recursive = -1;
        if ($uid != null) {
            $usr = $this->User->read(null, $uid);
            if (empty($usr)) {
                $uid = null;
            }
        }
        if ($uid == null || $uid == 1) { // the admin user can not be deleted!
            $this->Session->setFlash(__('The user does not exist!', true));
        }
        else {
            // remove user
            $this->User->delete($uid);
            $this->Session->setFlash(__('User deleted!', true).'('.$usr['User']['username'].')');
        }
        $this->redirect('/admins/users');
    }
    
    function gdelete($gid = null) {
        // check the group
        $this->Group->recursive = -1;
        if ($gid != null) {
            $grp = $this->Group->read(null, $gid);
            if (empty($grp)) {
                $gid = null;
            }
        }
        if ($gid == null || $gid == 1) { // the admin group can not be deleted!
            $this->Session->setFlash(__('The group does not exist!', true));
        }
        else {
            // check if there is some cases open in this group
            $this->Pol->recursive = -1;
            $grps_list = $this->Pol->find('all', array('conditions' => "group_id = $gid"));
            if (empty($grps_list)) {
                // remove group and all users
                $this->Group->delete($gid);
                $this->Session->setFlash(__('Group deleted!', true));
            }
            else {
                $this->Session->setFlash(__('Before delete this group you must delete all Cases of the group', true));
            }
        }
        $this->redirect('/admins/groups');
    }
    
    function index() {
        $this->redirect('/configurations');
    }
}
?>
