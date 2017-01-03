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
<?php echo $this->Form->create('Search',array( 'url' => array('controller' => 'feeds', 'action' => 'index')));
      echo $this->Form->input('label', array('type'=>'text','size' => '40','maxlength'=>'40', 'label'=> __('Search:'), 'default' => $srchd));
      echo $this->Form->end(__('Go'));?>
</center>

</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th><?php echo $this->Paginator->sort('name', __('Title')); ?></th>
	<th><?php echo $this->Paginator->sort('site', __('Site')); ?></th>
</tr>
<?php foreach ($feeds as $feed): ?>
  <tr>
	<td><b><?php echo $this->Html->link($feed['Feed']['name'],'/feeds/view/' . $feed['Feed']['id']); ?></b></td>
        <td><b><?php echo $feed['Feed']['site']; ?></b></td>
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
