<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">



<center>
<?php echo $this->Form->create('Search',array( 'url' => array('controller' => 'ircs', 'action' => 'index')));
      echo $this->Form->input('label', array('type'=>'text','size' => '40', 'label' => __('Search:'), 'default' => $srchd));
     echo $this->Form->end(__('Go'));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $this->Paginator->sort(__('Date'), 'capture_date'); ?></th>
	<th class="from"><?php echo $this->Paginator->sort(__('Url'), 'url'); ?></th>
	<th class="number"><?php echo $this->Paginator->sort(__('Channels'), 'channel_num'); ?></th>

</tr>
<?php foreach ($ircs as $irc): ?>
<?php if ($irc['Irc']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $irc['Irc']['capture_date']; ?></td>
	<td><?php echo $this->Html->link($irc['Irc']['url'],'/ircs/view/' . $irc['Irc']['id']); ?></td>
	<td><?php echo $irc['Irc']['channel_num']; ?></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $irc['Irc']['capture_date']; ?></b></td>
	<td><b><?php echo $this->Html->link($irc['Irc']['url'],'/ircs/view/' . $irc['Irc']['id']); ?></b></td>
	<td><b><?php echo $irc['Irc']['channel_num']; ?></b></td>
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
