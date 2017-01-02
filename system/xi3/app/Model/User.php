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

  class User extends AppModel
  {
    var $name = 'User';
    var $validate = null;
    var $belongsTo = array( 'Group' =>
                            array(
                                'className' => 'Group'
                                )
        );

    function __construct() {
        $this->validate = array(
            'username' => array(
                'urule1' => array(
                    'rule' => array('maxLength', 16),
                    'message' => __('Max user name size is 16'),
                    ),
                'urule2' => array(
                    'rule' => 'alphaNumeric',
                    'message' => __('Only Alpha Numeric chars!'),
                    ),
                'urule3' => array(
                    'rule' => array('minLength', 4),
                    'message' => __('The username must be more that 4 chars')
                    )
                ),
            'password' => array(
                'rule1' => array(
                    'rule' => 'alphaNumeric',
                    'message' => __('Only Alpha Numeric chars!')
                    ),
                'rule2' => array(
                    'rule' => array('minLength', 6),
                    'message' => __('The password must be more that 6 chars')
                    )
                ),
            'first_name' => array(
                'rule1' => array(
                    'rule' => '/^[a-z0-9 ]*$/i',
                    'message' => __('Only Alpha Numeric chars!'),
                    'allowEmpty' => true
                    ),
                'rule2' => array(
                    'rule' => array('minLength', 2),
                    'message' => __('The First name must be more that 2 chars'),
                    'allowEmpty' => true
                    )
                ),
            'last_name' => array(
                'rule1' => array(
                    'rule' => '/^[a-z0-9 ]*$/i',
                    'message' => __('Only Alpha Numeric chars!'),
                    'allowEmpty' => true
                    ),
                'rule2' => array(
                    'rule' => array('minLength', 2),
                    'message' => __('The Last name must be more that 2 chars'),
                    'allowEmpty' => true
                    ),
                ),
            'email' => array(
                'rule' => 'email',
                'message' => __('Please, a valid email!'),
                'required' => false
                )
            );
        parent::__construct();
    }
  }
?>