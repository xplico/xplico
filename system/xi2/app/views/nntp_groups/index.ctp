<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<script language="JavaScript">
    function popupVetrina(whatopen) {
      newWindow = window.open(whatopen, 'popup_vetrina', 'width=520,height=550,scrollbars=yes,toolbar=no,resizable=yes,menubar=no');
      return false;
    }
</script>
<div class="generic">
<div class="search">

<center>
<?php echo $form->create('Search',array( 'url' => array('controller' => 'nntp_groups', 'action' => 'index')));
      echo $form->input('label', array('type'=>'text','size' => '40','maxlength'=>'40', 'label'=> __('Search:', true), 'default' => $srchd));
      echo $form->end(__('Go', true));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th><?php echo $paginator->sort(__('Title', true), 'name'); ?></th>
</tr>
<?php foreach ($nntp_groups as $grp): ?>
  <tr>
	<td><b><?php echo $html->link($grp['Nntp_group']['name'],'/nntp_groups/grp/' . $grp['Nntp_group']['id']); ?></b></td>
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
