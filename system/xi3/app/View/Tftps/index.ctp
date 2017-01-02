<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">

<center>
<?php echo $this->Form->create('Search',array( 'url' => array('controller' => 'tftps', 'action' => 'index', 'label' => 'Search')));
      echo $this->Form->input('label', array('type'=>'text','size' => '40', 'label'=>__('Search:'), 'default' => $srchd));
      echo $this->Form->end(__('Go'));?>
</center>
</div>
<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $this->Paginator->sort(__('Date'), 'capture_date'); ?></th>
	<th class="from"><?php echo $this->Paginator->sort(__('Url'), 'url'); ?></th>
	<th class="number"><?php echo $this->Paginator->sort(__('Download'), 'download_num'); ?></th>
	<th class="number"><?php echo $this->Paginator->sort(__('Upload'), 'upload_num'); ?></th>

</tr>
<?php foreach ($tftps as $tftp): ?>
<?php if ($tftp['Tftp']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $tftp['Tftp']['capture_date']; ?></td>
	<td><?php echo $this->Html->link($tftp['Tftp']['url'],'/tftps/view/' . $tftp['Tftp']['id']); ?></td>
	<td><?php echo $tftp['Tftp']['download_num']; ?></td>
	<td><?php echo $tftp['Tftp']['upload_num']; ?></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $tftp['Tftp']['capture_date']; ?></b></td>
	<td><b><?php echo $this->Html->link($tftp['Tftp']['url'],'/tftps/view/' . $tftp['Tftp']['id']); ?></b></td>
	<td><b><?php echo $tftp['Tftp']['download_num']; ?></b></td>
	<td><b><?php echo $tftp['Tftp']['upload_num']; ?></b></td>
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
