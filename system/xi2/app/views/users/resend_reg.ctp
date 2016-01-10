<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<h1><?php __('This is a demo!'); ?></h1>
<p><?php __('Please fill out the form below to resubmit email account.'); ?></p>



<!-- NEW CODE FOR RESEND THE EMAIL -->
<?php echo $form->create('User',array( 'url' => array('controller' => 'users', 'action' => 'resend_reg')));
      echo $form->input('email', array('type'=>'text','size' => '40','maxlength'=>'255', 'label' => __('Email', true), 'error' => __('email is invalid', true)));
 echo $form->end(__('Go', true));?>

