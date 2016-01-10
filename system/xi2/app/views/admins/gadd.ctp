<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->

<div class="generic">
<h2><?php __('Please fill out the form below to add a new Group'); ?>.</h2>
<br />
<?php echo $form->create('Admin', array('action'=>'gadd'));
      echo $form->input('Group.name', array('label' => __('Name', true), 'type'=>'text', 'size' => '40','maxlength'=>'40', 'error' => $name_error));
      echo $form->end(__('Confim', true)); ?>
      <div class="cline"> </div>

</div>
