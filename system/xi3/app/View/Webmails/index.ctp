<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">


<center>
<?php echo $this->Form->create('Webmails', array( 'url' => array('controller' => 'webmails', 'action' => 'index')));
      echo $this->Form->input('search',  array( 'type'=>'text','size' => '40', __('Search'), 'default' => $srchd));
echo $this->Form->end(__('Go'));
?>
</center>
</div>
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $this->Paginator->sort(__('Date'), 'capture_date'); ?></th>
	<th class="subject"><?php echo $this->Paginator->sort(__('Subject'), 'subject'); ?></th>
	<th class="from"><?php echo $this->Paginator->sort(__('Sender'), 'sender'); ?></th>
	<th class="to"><?php echo $this->Paginator->sort(__('Receivers'), 'receivers'); ?></th>
	<th class="size"><?php echo $this->Paginator->sort(__('Service'), 'service'); ?></th>
	<th class="size"><?php echo $this->Paginator->sort(__('Size'), 'data_size'); ?></th>
 </tr>
 <?php foreach ($emails as $email): ?>
 <?php if ($email['Webmail']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $email['Webmail']['capture_date']; ?></td>
        <?php if ($email['Webmail']['subject'] == "") : ?>
        <td><?php echo $this->Html->link("--",'/webmails/view/' . $email['Webmail']['id']); ?></td>
        <?php else : ?>
	<td><?php echo $this->Html->link(htmlentities($email['Webmail']['subject']), '/webmails/view/' . $email['Webmail']['id']); ?></td>
        <?php endif; ?>
	<td><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $email['Webmail']['sender'])); ?></td>
	<td><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $email['Webmail']['receivers'])); ?></td>
	<td><?php echo $email['Webmail']['service']; ?></td>
	<td><?php echo $email['Webmail']['data_size']; ?></td>
  </tr>
 <?php else : ?>
  <tr>
	<td><b><?php echo $email['Webmail']['capture_date']; ?></b></td>
        <?php if ($email['Webmail']['subject'] == "") : ?>
        <td><b><?php echo $this->Html->link("--",'/webmails/view/' . $email['Webmail']['id']); ?></b></td>
        <?php else : ?>
	<td><b><?php echo $this->Html->link(htmlentities($email['Webmail']['subject']), '/webmails/view/' . $email['Webmail']['id']); ?></b></td>
        <?php endif; ?>
	<td><b><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $email['Webmail']['sender'])); ?></b></td>
	<td><b><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $email['Webmail']['receivers'])); ?></b></td>
	<td><b><?php echo $email['Webmail']['service']; ?></b></td>
	<td><b><?php echo $email['Webmail']['data_size']; ?></b></td>
  </tr>
 <?php endif; ?>
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
