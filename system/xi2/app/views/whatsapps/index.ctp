<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">


<center>
<?php echo $form->create('Whatsapps', array( 'url' => array('controller' => 'whatsapps', 'action' => 'index')));
      echo $form->input('search',  array( 'type'=>'text','size' => '40', 'label' => __('Search', true), 'default' => $srchd));
echo $form->end(__('Go', true));
?>
</center>
</div>
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="subject"><?php echo $paginator->sort(__('Device', true), 'device'); ?></th>
	<th class="size"><?php echo $paginator->sort(__('Phone', true), 'phone'); ?></th>
 </tr>
 <?php foreach ($whatsapps as $whatsapp): ?>
 <?php if ($whatsapp['Whatsapp']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $whatsapp['Whatsapp']['capture_date']; ?></td>
	<td><?php echo $html->link($whatsapp['Whatsapp']['device'],'/whatsapps/view/' . $whatsapp['Whatsapp']['id']); ?></td>
	<td><?php echo $whatsapp['Whatsapp']['log_size']; ?></td>
  </tr>
 <?php else : ?>
  <tr>
	<td><b><?php echo $whatsapp['Whatsapp']['capture_date']; ?></b></td>
	<td><b><?php echo $html->link($whatsapp['Whatsapp']['phone'],'/whatsapps/view/' . $whatsapp['Whatsapp']['id']); ?></b></td>
	<td><b><?php echo $whatsapp['Whatsapp']['log_size']; ?></b></td>
  </tr>
 <?php endif ?>
<?php endforeach; ?>
</table>
<table id="listpage" summary="Message list" cellspacing="0">
<tr>
	<th class="next"><?php echo $paginator->prev(__('Previous', true), array(), null, array('class'=>'disabled')); ?></th>
       	<th><?php echo $paginator->numbers(); echo '<br/>'.$paginator->counter(); ?></th>
	<th class="next"><?php echo $paginator->next(__('Next', true), array(), null, array('class' => 'disabled')); ?></th>
</tr>
</table>
</div>
