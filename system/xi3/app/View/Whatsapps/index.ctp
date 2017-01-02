<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">


<center>
<?php echo $this->Form->create('Whatsapps', array( 'url' => array('controller' => 'whatsapps', 'action' => 'index')));
      echo $this->Form->input('search',  array( 'type'=>'text','size' => '40', 'label' => __('Search'), 'default' => $srchd));
echo $this->Form->end(__('Go'));
?>
</center>
</div>
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $this->Paginator->sort(__('Date'), 'capture_date'); ?></th>
	<th class="subject"><?php echo $this->Paginator->sort(__('Device'), 'device'); ?></th>
	<th class="size"><?php echo $this->Paginator->sort(__('Phone'), 'phone'); ?></th>
 </tr>
 <?php foreach ($whatsapps as $whatsapp): ?>
 <?php if ($whatsapp['Whatsapp']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $whatsapp['Whatsapp']['capture_date']; ?></td>
	<td><?php echo $this->Html->link($whatsapp['Whatsapp']['device'],'/whatsapps/view/' . $whatsapp['Whatsapp']['id']); ?></td>
	<td><?php echo $whatsapp['Whatsapp']['log_size']; ?></td>
  </tr>
 <?php else : ?>
  <tr>
	<td><b><?php echo $whatsapp['Whatsapp']['capture_date']; ?></b></td>
	<td><b><?php echo $this->Html->link($whatsapp['Whatsapp']['phone'],'/whatsapps/view/' . $whatsapp['Whatsapp']['id']); ?></b></td>
	<td><b><?php echo $whatsapp['Whatsapp']['log_size']; ?></b></td>
  </tr>
 <?php endif ?>
<?php endforeach; ?>
</table>
<table id="listpage" summary="Message list" cellspacing="0">
<tr>
	<th class="next"><?php echo $this->Paginator->prev(__('Previous'), array(), null, array('class'=>'disabled')); ?></th>
       	<th><?php echo $this->Paginator->numbers(); echo '<br/>'.$this->Paginator->counter(); ?></th>
	<th class="next"><?php echo $this->Paginator->next(__('Next'), array(), null, array('class' => 'disabled')); ?></th>
</tr>
</table>
</div>
