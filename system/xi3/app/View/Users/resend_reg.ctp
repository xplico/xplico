<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<h1><?php echo __('This is a demo!'); ?></h1>
<p><?php echo __('Please fill out the form below to resubmit email account.'); ?></p>



<!-- NEW CODE FOR RESEND THE EMAIL -->
<?php echo $this->Form->create('User',array( 'url' => array('controller' => 'users', 'action' => 'resend_reg')));
      echo $this->Form->input('email', array('type'=>'text','size' => '40','maxlength'=>'255', 'label' => __('Email'), 'error' => __('email is invalid')));
 echo $this->Form->end(__('Go'));?>

