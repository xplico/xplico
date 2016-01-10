<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->

<div class="generic">
<h2><?php __('Please fill out the form below to add a new User'); ?>.</h2>
<br />
<?php echo $form->create('Admin', array('action'=>'uadd'));
      echo $form->input('User.username', array('label' => __('User name', true), 'type'=>'text','size' => '40','maxlength'=>'40', 'error' => $username_error));
      echo $form->input('User.password', array('label' => __('Password', true), 'type'=>'password','size' => '40','maxlength'=>'40'));
      echo $form->input('User.email', array('label' => __('Email', true), 'type'=>'text','size' => '40','maxlength'=>'40'));
      echo $form->input('User.first_name', array('label' => __('First Name', true), 'type'=>'text','size' => '40','maxlength'=>'40'));
      echo $form->input('User.last_name', array('label' => __('Last Name', true), 'type'=>'text','size' => '40','maxlength'=>'40'));
      echo '<div class="cline"> </div>';
      echo $form->input('group_id', array('label' =>  __('Group', true)));
      echo '<div class="cline"> </div>';
      echo $form->end(__('Confim', true)); ?>
      <div class="cline"> </div>
</div>
