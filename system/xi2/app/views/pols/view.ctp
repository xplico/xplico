<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="pol">
<h2><?php __('View Case'); ?></h2>

<dl>
	<dt><?php __('Name'); ?></dt>
	<dd>&nbsp;<?php echo $pol['Pol']['name']; ?></dd>
	<dt><?php __('External Reference'); ?></dt>
	<dd>&nbsp;<?php echo $pol['Pol']['external_ref']; ?></dd>
</dl>

</div>
<div class="related">
<h3><?php __('Related Sols'); ?></h3>
<?php if(!empty($pol['Sol'])):?>
<table cellpadding="0" cellspacing="0">
<tr>
<?php foreach($pol['Sol']['0'] as $column => $value): ?>
<th><?php echo $column?></th>
<?php endforeach; ?>
<th>Actions</th>
</tr>
<?php foreach($pol['Sol'] as $sol):?>
<tr>
	<?php foreach($sol as $column => $value):?>
		<td><?php echo $value;?></td>
	<?php endforeach;?>
	<td class="actions">
		<?php echo $html->link(__('View', true), '/sols/view/' . $sol['id']);?>
		<?php echo $html->link(__('Delete', true), '/sols/delete/' . $sol['id'], null, 'Are you sure you want to delete: id ' . $sol['id'] . '?');?>
	</td>
</tr>
<?php endforeach; ?>
</table>
<?php endif; ?>


</div>
<div class="related">
<h3>Related Emails</h3>
<?php if(!empty($pol['Email'])):?>
<table cellpadding="0" cellspacing="0">
<tr>
<?php foreach($pol['Email']['0'] as $column => $value): ?>
<th><?php echo $column?></th>
<?php endforeach; ?>
<th>Actions</th>
</tr>
<?php foreach($pol['Email'] as $email):?>
<tr>
	<?php foreach($email as $column => $value):?>
		<td><?php echo $value;?></td>
	<?php endforeach;?>
	<td class="actions">
		<?php echo $html->link('View', '/emails/view/' . $email['id']);?>
		<?php echo $html->link('Edit', '/emails/edit/' . $email['id']);?>
		<?php echo $html->link('Delete', '/emails/delete/' . $email['id'], null, 'Are you sure you want to delete: id ' . $email['id'] . '?');?>
	</td>
</tr>
<?php endforeach; ?>
</table>
<?php endif; ?>


</div>
<div class="related">
<h3>Related Files</h3>
<?php if(!empty($pol['File'])):?>
<table cellpadding="0" cellspacing="0">
<tr>
<?php foreach($pol['File']['0'] as $column => $value): ?>
<th><?php echo $column?></th>
<?php endforeach; ?>
<th>Actions</th>
</tr>
<?php foreach($pol['File'] as $file):?>
<tr>
	<?php foreach($file as $column => $value):?>
		<td><?php echo $value;?></td>
	<?php endforeach;?>
	<td class="actions">
		<?php echo $html->link('View', '/files/view/' . $file['id']);?>
		<?php echo $html->link('Edit', '/files/edit/' . $file['id']);?>
		<?php echo $html->link('Delete', '/files/delete/' . $file['id'], null, 'Are you sure you want to delete: id ' . $file['id'] . '?');?>
	</td>
</tr>
<?php endforeach; ?>
</table>
<?php endif; ?>


</div>