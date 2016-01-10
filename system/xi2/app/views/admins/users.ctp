<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
	<h2><?php echo __('Users of', true).' '.$group; ?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr id='items'>
			<th><?php echo $paginator->sort(__('User', true), 'username'); ?></th>
			<th><?php echo $paginator->sort(__('First Name', true), 'first_name'); ?></th>
			<th><?php echo $paginator->sort(__('Last Name', true), 'last_name'); ?></th>
			<th><?php echo $paginator->sort(__('Email', true), 'email'); ?></th>
			<th><?php echo $paginator->sort(__('Last Login', true), 'last_login'); ?></th>
                        <th><?php echo $paginator->sort(__('Count', true), 'login_num'); ?></th>
			<th><?php __('Actions'); ?></th>
	</tr>
	<?php
	foreach ($users as $user):
	?>
	<tr>
		<td><?php echo $user['User']['username']; ?></td>
		<td><?php echo $user['User']['first_name']; ?></td>
		<td><?php echo $user['User']['last_name']; ?></td>
		<td><?php echo $user['User']['email']; ?></td>
		<td><?php echo $user['User']['last_login']; ?></td>
                <td><?php echo $user['User']['login_num']; ?></td>
		<td class="actions">
		<?php 
                     if ($user['User']['id'] != 1) echo $html->link(__('Delete', true),'/admins/udelete/' . $user['User']['id'], null, __('Are you sure you want to delete the user', true). ' \'' . $user['User']['username'] . '\' ?').', ';
                     echo $html->link(__('Password', true),'/users/cpassword/' . $user['User']['id'], null);
                ?>
		</td>
	</tr>
       <?php endforeach; ?>
	</table>

</table>
<table id="listpage" summary="Message list" cellspacing="0">
<tr>
<th class="next"><?php echo $paginator->prev(__('Previous', true), array(), null, array('class'=>'disabled')); ?></th>
<th><?php echo $paginator->numbers(); echo '<br/>'.$paginator->counter(); ?></th>
<th class="next"><?php echo $paginator->next(__('Next', true), array(), null, array('class' => 'disabled')); ?></th>
</tr>
</table>
</div>