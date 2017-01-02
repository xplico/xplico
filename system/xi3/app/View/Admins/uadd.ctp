<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->

<div class="generic">
<h2><?php echo __('Please fill out the form below to add a new User'); ?>.</h2>
<br />
<?php echo $this->Form->create('Admin', array('url' => array('action'=>'uadd')));
      echo $this->Form->input('User.username', array('label' => __('User name'), 'type'=>'text','size' => '40','maxlength'=>'40', 'error' => $username_error));
      echo $this->Form->input('User.password', array('label' => __('Password'), 'type'=>'password','size' => '40','maxlength'=>'40'));
      echo $this->Form->input('User.email', array('label' => __('Email'), 'type'=>'text','size' => '40','maxlength'=>'40'));
      echo $this->Form->input('User.first_name', array('label' => __('First Name'), 'type'=>'text','size' => '40','maxlength'=>'40'));
      echo $this->Form->input('User.last_name', array('label' => __('Last Name'), 'type'=>'text','size' => '40','maxlength'=>'40'));
      echo '<div class="cline"> </div>';
      echo $this->Form->input('group_id', array('label' =>  __('Group')));
      echo '<div class="cline"> </div>';
      echo $this->Form->end(__('Confim')); ?>
      <div class="cline"> </div>
</div>
