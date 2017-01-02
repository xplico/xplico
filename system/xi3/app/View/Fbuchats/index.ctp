<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">
<?php echo $this->Form->create('Search', array( 'url' => array('controller' => 'fbuchats', 'action' => 'index')));
      echo $this->Form->input('label', array('type'=>'text','size' => '40','maxlength'=>'40', 'label'=> __('Search:'), 'default' => $srchd));
      echo $this->Form->end(__('Go'));
?>

</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th><?php echo $this->Paginator->sort(__('Users'), 'username'); ?></th>
</tr>
<?php foreach ($fb_users as $user): ?>
  <tr>
        <td><b><a href="<?php echo '/fbuchats/user/' . $user['Fbuchat']['id']; ?>"><script type="text/javascript"> var txt="<?php echo $user['Fbuchat']['username']; ?>"; document.write(txt); </script></a></b></td>
  </tr>
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
