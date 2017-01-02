<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">


<center>
<?php echo $this->Form->create('Emails', array( 'url' => array('controller' => 'emails', 'action' => 'index')));
      echo $this->Form->input('search',  array( 'type'=>'text','size' => '40', 'default' => $srchd, 'label' => __('Search')));
      echo $this->Form->input('relevance', array('options' => $relevanceoptions, 'label' => __('Choose relevance'), 'empty' => __('None')));
      echo $this->Form->end(__('Go'));
?>
</center>
</div>

<br />
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $this->Paginator->sort(__('Date'), 'capture_date'); ?></th>
	<th class="subject"><?php echo $this->Paginator->sort(__('Subject'), 'subject'); ?></th>
	<th class="from"><?php echo $this->Paginator->sort(__('Sender'), 'sender'); ?></th>
	<th class="to"><?php echo $this->Paginator->sort(__('Receivers'), 'receivers'); ?></th>
	<th class="size"><?php echo $this->Paginator->sort(__('Size'), 'data_size'); ?></th>
<!--	<th class="relevance"><?php echo $this->Paginator->sort(__('Relevance'), 'relevance'); ?> -->
<th class="relevance"><?php echo $this->Paginator->sort('relevance'); ?>
		<a href="/relevance.html" 
		onclick="window.open('/relevance.html','popup','width=500,height=500,scrollbars=no,resizable=no,toolbar=no,directories=no,location=no,menubar=no,status=no,left=0,top=0'); 
		return false">(?)</a>
	</th>
 </tr>
 <?php foreach ($emails as $email): ?>
 <?php if ($email['Email']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $email['Email']['capture_date']; ?></td>
        <?php if ($email['Email']['subject'] == '' || $email['Email']['subject'] == ' ') : ?>
        <td><?php echo $this->Html->link("--",'/emails/view/' . $email['Email']['id']); ?></td>
        <?php else : ?>
        <?php if (strpos($email['Email']['subject'], '=?') != 0): ?>
	<td><?php echo $this->Html->link(htmlentities($email['Email']['subject']), '/emails/view/' . $email['Email']['id']); ?></td>
        <?php else : ?>
        <td><?php echo $this->Html->link($email['Email']['subject'], '/emails/view/' . $email['Email']['id']); ?></td>
        <?php endif; ?>
        <?php endif; ?>
	<td><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $email['Email']['sender'])); ?></td>
	<td><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $email['Email']['receivers'])); ?></td>
	<td><?php echo $email['Email']['data_size']; ?></td>
	<td><?php 
		if (  (0 <=  $email['Email']['relevance']) &&  ($email['Email']['relevance'] < 6) ) {
		echo $email['Email']['relevance'];
		}
	else {
		__('Unknown'); }

		?></td>
  </tr>
 <?php else : ?>
  <tr>
	<td><b><?php echo $email['Email']['capture_date']; ?></b></td>
        <?php if ($email['Email']['subject'] == '' || $email['Email']['subject'] == ' ') : ?>
        <td><b><?php echo $this->Html->link("--",'/emails/view/' . $email['Email']['id']); ?></b></td>
        <?php else : ?>
        <?php if (strpos($email['Email']['subject'], '=?') != 0): ?>
	<td><b><?php echo $this->Html->link(htmlentities($email['Email']['subject']), '/emails/view/' . $email['Email']['id']); ?></b></td>
        <?php else : ?>
	<td><b><?php echo $this->Html->link($email['Email']['subject'], '/emails/view/' . $email['Email']['id']); ?></b></td>
        <?php endif; ?>
        <?php endif; ?>
	<td><b><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $email['Email']['sender'])); ?></b></td>
	<td><b><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $email['Email']['receivers'])); ?></b></td>
	<td><b><?php echo $email['Email']['data_size']; ?></b></td>

	<td><b>

		<?php 
		if (  (0 <=  $email['Email']['relevance']) &&  ($email['Email']['relevance'] < 6) ) {
		echo $email['Email']['relevance'];
		}

	else {
		__('Unknown'); }
		?>



	</b></td>
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
