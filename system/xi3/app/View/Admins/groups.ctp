<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
	<h2><?php echo __('Groups'); ?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr id='items'>
			<th><?php echo __('Group'); ?></th>
			<th><?php echo __('Actions');?></th>
	</tr>
	<?php
	foreach ($groups as $group):
	?>
	<tr>
		<td><?php echo $group['Group']['name']; ?>&nbsp;</td>
		<td class="actions">
		<?php 
                      echo $this->Html->link(__('Users'),'/admins/users/' . $group['Group']['id']);
                      echo ' , '.$this->Html->link(__('Cases'),'/pols/index/' . $group['Group']['id']);
                      if ($group['Group']['id'] != 1) echo ' , '.$this->Html->link(__('Delete'), '/admins/gdelete/' . $group['Group']['id'], null, __('Are you sure you want to delete group').'\'' . $group['Group']['name'] . '\'?');
                ?>
		</td>
	</tr>
       <?php endforeach; ?>
	</table>

</div>
