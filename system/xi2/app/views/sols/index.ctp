<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->

<div class="sols">
<h2><?php __('List of listening sessions of case:'); ?> <font color="red"><?php echo $pol_name; ?></font></h2>

<table cellpadding="0" cellspacing="0">
<tr>
	<th><?php __('Name'); ?></th>
	<th><?php __('Start Time'); ?></th>
	<th><?php __('End Time'); ?></th>
	<th><?php __('Status'); ?></th>
	<th><?php __('Actions'); ?></th>
</tr>
<?php $i = 0; ?>
<?php foreach ($sols as $sol): ?>
<tr>
	<td><?php echo $html->link($sol['Sol']['name'],'/sols/view/' . $sol['Sol']['id']); ?></td>
	<td><?php if ($sol['Sol']['start_time'] != '1990-01-01 00:00:00') echo $sol['Sol']['start_time']; else echo '---'; ?></td>
	<td><?php if ($sol['Sol']['start_time'] != '1990-01-01 00:00:00') echo $sol['Sol']['end_time']; else echo '---'; ?></td>
	<td><?php echo $sol['Sol']['status']; ?></td>
	<td class="actions">
		<?php
                    $i++;
                    if ($i != 1)
                        echo $html->link(__('Delete', true),'/sols/delete/' . $sol['Sol']['id'], null, 'Are you sure you want to delete \'' . $sol['Sol']['name'] . '\'')
                ?>
	</td>
</tr>
<?php endforeach; ?>
</table>

</div>
