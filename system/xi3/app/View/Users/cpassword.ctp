<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2017, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
    <h2><?php echo __('Change password'); ?></h2>
    <br/>
    <?php echo $this->Form->create('User', array('url' => array('action'=>'cpassword')));?>
      <?php echo $this->Form->input('id', array('type' => 'hidden', 'value' => $id));?>
      <?php echo $this->Form->input('opassword', array('type'=>'password', 'maxlength' => 40, 'label' => __('Old password'))); ?>
      <div class="cline"> </div>
      <?php echo $this->Form->input('password', array('type'=>'password', 'maxlength' => 40, 'label' => __('New password'))); ?>
      <div class="cline"> </div>
      <?php echo $this->Form->input('rpassword', array('type'=>'password', 'maxlength' => 40, 'label' => __('Repeat new password'))); ?>
      <div class="cline"> </div>
      <?php echo $this->Form->submit(__('Ok'), array('div' => false));?>
    <?php echo $this->Form->end();?>
</div>
