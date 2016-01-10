<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
	<h2><?php __('Groups'); ?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr id='items'>
			<th><?php __('Group'); ?></th>
			<th><?php __('Actions');?></th>
	</tr>
	<?php
	foreach ($groups as $group):
	?>
	<tr>
		<td><?php echo $group['Group']['name']; ?>&nbsp;</td>
		<td class="actions">
		<?php 
                      echo $html->link(__('Users', true),'/admins/users/' . $group['Group']['id']);
                      echo ' , '.$html->link(__('Cases', true),'/pols/index/' . $group['Group']['id']);
                      if ($group['Group']['id'] != 1) echo ' , '.$html->link(__('Delete', true), '/admins/gdelete/' . $group['Group']['id'], null, __('Are you sure you want to delete group', true).'\'' . $group['Group']['name'] . '\'?');
                ?>
		</td>
	</tr>
       <?php endforeach; ?>
	</table>

</div>
