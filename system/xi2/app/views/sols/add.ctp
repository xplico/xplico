<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="sols">
<h2><?php __('New listening session'); ?></h2>

<?php echo $form->create('Sol');
      echo "<br /><br />";
      echo $form->input('Sol.name',  array('maxlength'=> 50, 'size' => '50', 'label' => __('Session name', true)));
      echo '<div class="cline"> </div>';
echo $form->end(__('Create', true));
?>
</div>
