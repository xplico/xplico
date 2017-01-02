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

class PolsController extends AppController {
    var $name = 'Pols';
    var $helpers = array('Html', 'Form');
    var $uses = array('Param', 'Pol', 'Group');
    
    function beforeFilter() {
        $groupid = $this->Session->read('group');
        if (!$groupid) {
            $this->redirect('/users/login');
        }
        $this->Session->delete('pol');
        $this->Session->delete('sol');
    }
    
    function index($gid = null) {
        $groupid = $this->Session->read('group');
        $this->Pol->recursive = -1;
        $filtr = '';
        if (!$this->Session->check('admin')) {
            $filtr = 'group_id = '.$groupid;
        }
        else if ($gid != null) {
            $this->Group->recursive = -1;
            $grp = $this->Group->read(null, $gid);
            if (empty($grp)) {
                $gid = null;
            }
            if ($gid != null) {
                $filtr = 'group_id = '.$gid;
            }
        }
        $this->set('pols', $this->Pol->find('all', array('conditions' => $filtr, 'order' => 'Pol.id DESC')));
        if ($this->Session->check('admin')) {
            $this->set('menu_left', 
                       array('active' => '0', 'sections' => array(
                                 array('name' => __('Case'), 'sub' => array(
                                           array('name' => __('Cases'), 'link' => '/pols')
                                           )
                                     )
                                 )
                           )
                );
        }
        else {
            $this->set('menu_left', 
                   array('active' => '0', 'sections' => array(
                             array('name' => __('Case'), 'sub' => array(
                                       array('name' => __('Cases'), 'link' => '/pols'),
                                       array('name' => __('New Case'), 'link' => '/pols/add')
                                       )
                                 )
                             )
                       )
            );
        }
    }
    
    function view($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for Case.'));
            $this->redirect('/pols/index');
        }
        $this->Pol->recursive = -1;
        $pol = $this->Pol->read('group_id', $id);
        if ($pol['Pol']['group_id'] == $this->Session->read('group') || $this->Session->check('admin')) {
            $this->set('pol', $pol);
            $this->Session->write('pol', $id);
            // temporaney
            $this->redirect('/sols/index');
        }
        else {
            $this->redirect('/pols/index');
        }
    }
    
    function add() {
        if ($this->Session->check('admin')) {
            $this->Session->setFlash(__('Administrators can not create new Cases or new Sessions!'));
            $this->redirect('/pols/index');
        }
        $this->set('menu_left', 
                   array('active' => '0', 'sections' => array(
                             array('name' => __('Case'), 'sub' => array(
                                       array('name' => __('Cases'), 'link' => '/pols'),
                                       array('name' => __('New Case'), 'link' => '/pols/add')
                                       )
                                 )
                             )
                       )
            );
        $register = $this->Param->findByName('register');
        $this->set('register', $register['Param']['nvalue']);
        if (!empty($this->request->data)) {
            $register = $this->Param->findByName('register');
            if ($register['Param']['nvalue'] == 0)
                $this->request->data['Pol']['realtime'] = $this->request->data['Capture']['Type'];
            else
                $this->request->data['Pol']['realtime'] = 0;
            $this->request->data['Pol']['group_id'] = $this->Session->read('group');
            if($this->Pol->save(Sanitize::paranoid($this->request->data))) {
                $this->Session->setFlash(__('The Case has been created'));
                $this->redirect('/pols/index');
            } else {
                $this->Session->setFlash(__('Please correct errors below.'));
            }
        }
    }
    
    function delete($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for Case'));
            $this->redirect('/pols/index');
        }
        $this->Pol->recursive = -1;
        $pol = $this->Pol->read(null, $id);
        if ($pol['Pol']['group_id'] != $this->Session->read('group') || $this->Session->check('admin')) {
            if ($this->Session->check('admin')) {
                $this->Session->setFlash(__('Admin can not delete the cases'));
            }
            else {
                $this->Session->setFlash(__('Invalid id for the Case'));
            }
            $this->redirect('/pols/index');
        }
        // delete directory: send info to dema
        $pol_dir = '/opt/xplico/pol_'.$id;
        if (file_exists($pol_dir)) {
            /* exist at least one session */
            $del_pol_file = $pol_dir.'/delete';
            $fp = fopen($del_pol_file, 'aw');
            fclose($fp);
            // wait records db cancellation
            do {
                sleep(1);
            } while (file_exists($del_pol_file));
        }
        else {
            /* the case is only in the DB record */
            $this->Pol->delete($id);
        }
        $this->Session->setFlash(__('Case deleted'));
        
        $this->redirect('/pols/index');
    }
}
?>
