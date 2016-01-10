<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
    <h2><?php __('Change password'); ?></h2>
    <br/>
    <?php echo $form->create('User', array('action'=>'cpassword'));?>
      <?php echo $form->input('id', array('type' => 'hidden', 'value' => $id));?>
      <?php echo $form->input('opassword', array('type'=>'password', 'maxlength' => 40, 'label' => __('Old password', true))); ?>
      <div class="cline"> </div>
      <?php echo $form->input('password', array('type'=>'password', 'maxlength' => 40, 'label' => __('New password', true))); ?>
      <div class="cline"> </div>
      <?php echo $form->input('rpassword', array('type'=>'password', 'maxlength' => 40, 'label' => __('Repeat new password', true))); ?>
      <div class="cline"> </div>
      <?php echo $form->submit(__('Ok', true), array('div' => false));?>
    <?php echo $form->end();?>
</div>
