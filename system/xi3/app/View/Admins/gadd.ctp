<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->

<div class="generic">
<h2><?php echo __('Please fill out the form below to add a new Group'); ?>.</h2>
<br />
<?php echo $this->Form->create('Admin', array('url' => array('action'=>'gadd')));
      echo $this->Form->input('Group.name', array('label' => __('Name'), 'type'=>'text', 'size' => '40','maxlength'=>'40', 'error' => $name_error));
      echo $this->Form->end(__('Confim')); ?>
      <div class="cline"> </div>

</div>
