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

class InputsController extends AppController {

	var $name = 'Inputs';
	var $helpers = array('Html', 'Form', 'Javascript');
        var $components = array( 'Xplico');

        function beforeFilter() {
                $groupid = $this->Session->read('group');
                $polid = $this->Session->read('pol');
                $solid = $this->Session->read('sol');
                if (!$groupid || !$polid || !$solid) {
                    $this->redirect('/users/login');
                }
        }

        function index() {
                $solid = $this->Session->read('sol');
                $this->Input->recursive = -1;
                $this->set('inputs', $this->Input->find('all', array('conditions' => ("sol_id = $solid"))));
                $this->set('menu_left', $this->Xplico->leftmenuarray(0) );
        }

        function geomap() {
                $solid = $this->Session->read('sol');
                $this->Input->recursive = -1;
                $this->set('inputs', $this->Input->find('all', array('conditions' => ("sol_id = $solid"))));
                $this->set('menu_left', $this->Xplico->leftmenuarray(1) );

        }


        function kml_file($id_data = null) {
            if (!$id_data) {
                exit();
            }
            $polid = $this->Session->read('pol');
            $solid = $this->Session->read('sol');
            $this->Input->recursive = -1;
            $kml = $this->Input->read(null, $id_data);
            if ($polid != $kml['Input']['pol_id'] || $solid != $kml['Input']['sol_id']) {
                $this->redirect('/users/login');
            }
            else {
                $file_path = '/opt/xplico/pol_' . $polid . '/sol_' . $solid . '/gea/' . $kml['Input']['filename'] . '.kml';
                $this->autoRender = false;
                header("Content-Disposition: filename=" . $kml['Input']['filename'] . '.kml');
                header("Content-Type: application/vnd.google-earth.kml+xml; charset=UTF-8");
                header("Content-Length: " . filesize($file_path));
                readfile($file_path);
                //print_r($mm_data);
                exit();
            }
        }
}
?>
