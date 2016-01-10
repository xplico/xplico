<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">
<?php echo $form->create('Search', array( 'url' => array('controller' => 'fbuchats', 'action' => 'index')));
      echo $form->input('label', array('type'=>'text','size' => '40','maxlength'=>'40', 'label'=> __('Search:', true), 'default' => $srchd));
      echo $form->end(__('Go', true));
?>

</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th><?php echo $paginator->sort(__('Users', true), 'username'); ?></th>
</tr>
<?php foreach ($fb_users as $user): ?>
  <tr>
        <td><b><a href="<?php echo '/fbuchats/user/' . $user['Fbuchat']['id']; ?>"><script type="text/javascript"> var txt="<?php echo $user['Fbuchat']['username']; ?>"; document.write(txt); </script></a></b></td>
  </tr>
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
