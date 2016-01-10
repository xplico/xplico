<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">


<center>
<?php echo $form->create('Webmails', array( 'url' => array('controller' => 'webmails', 'action' => 'index')));
      echo $form->input('search',  array( 'type'=>'text','size' => '40', __('Search', true), 'default' => $srchd));
echo $form->end(__('Go', true));
?>
</center>
</div>
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="subject"><?php echo $paginator->sort(__('Subject', true), 'subject'); ?></th>
	<th class="from"><?php echo $paginator->sort(__('Sender', true), 'sender'); ?></th>
	<th class="to"><?php echo $paginator->sort(__('Receivers', true), 'receivers'); ?></th>
	<th class="size"><?php echo $paginator->sort(__('Service', true), 'service'); ?></th>
	<th class="size"><?php echo $paginator->sort(__('Size', true), 'data_size'); ?></th>
 </tr>
 <?php foreach ($emails as $email): ?>
 <?php if ($email['Webmail']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $email['Webmail']['capture_date']; ?></td>
        <?php if ($email['Webmail']['subject'] == "") : ?>
        <td><?php echo $html->link("--",'/webmails/view/' . $email['Webmail']['id']); ?></td>
        <?php else : ?>
	<td><?php echo $html->link(htmlentities($email['Webmail']['subject']), '/webmails/view/' . $email['Webmail']['id']); ?></td>
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
        <td><b><?php echo $html->link("--",'/webmails/view/' . $email['Webmail']['id']); ?></b></td>
        <?php else : ?>
	<td><b><?php echo $html->link(htmlentities($email['Webmail']['subject']), '/webmails/view/' . $email['Webmail']['id']); ?></b></td>
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
	<th class="next"><?php echo $paginator->prev(__('Previous', true), array(), null, array('class'=>'disabled')); ?></th>
       	<th><?php echo $paginator->numbers(); echo '<br/>'.$paginator->counter(); ?></th>
	<th class="next"><?php echo $paginator->next(__('Next', true), array(), null, array('class' => 'disabled')); ?></th>
</tr>
</table>
</div>
