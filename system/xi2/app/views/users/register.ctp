<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div id="register" align="center">
<h1><?php __('Please fill out the form below to register an account.'); ?></h1>
<br />
<?php echo $this->Form->create('User');
      echo $this->Form->input('email', array('type'=>'text','size' => '40','maxlength'=>'40', 'label' => __('Email', true)));
      echo $this->Form->input('username', array('type'=>'text','size' => '40','maxlength'=>'40', 'label' => __('Username', true)));
      echo $this->Form->input('password', array('type'=>'password','size' => '40','maxlength'=>'40', 'label' => __('Password', true)));
     
      if (0) {
      echo $this->Form->input('first_name', array('type'=>'text','size' => '40','maxlength'=>'40', 'label' => __('First Name', true)));
      echo $this->Form->input('last_name', array('type'=>'text','size' => '40','maxlength'=>'40', 'label' => __('Last Name', true), 'error' => __('Last Name is required', true)));
      }
      echo $this->Form->end(__('Confirm', true)); ?>
      <div class="cline"> </div>
</div>