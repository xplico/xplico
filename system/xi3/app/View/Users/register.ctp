<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div id="register" align="center">
<h1><?php echo __('Please fill out the form below to register an account.'); ?></h1>
<br />
<?php echo $this->Form->create('User');
      echo $this->Form->input('email', array('type'=>'text','size' => '40','maxlength'=>'40', 'label' => __('Email')));
      echo $this->Form->input('username', array('type'=>'text','size' => '40','maxlength'=>'40', 'label' => __('Username')));
      echo $this->Form->input('password', array('type'=>'password','size' => '40','maxlength'=>'40', 'label' => __('Password')));
     
      if (0) {
      echo $this->Form->input('first_name', array('type'=>'text','size' => '40','maxlength'=>'40', 'label' => __('First Name')));
      echo $this->Form->input('last_name', array('type'=>'text','size' => '40','maxlength'=>'40', 'label' => __('Last Name'), 'error' => __('Last Name is required')));
      }
      echo $this->Form->end(__('Confirm')); ?>
      <div class="cline"> </div>
</div>