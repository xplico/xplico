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
<?php echo $this->Form->create('Search',array( 'url' => array('controller' => 'mms', 'action' => 'index')));
      echo $this->Form->input('label', array('type'=>'text','size' => '40', 'label'=> __('Search:'), 'default' => $srchd));
      echo $this->Form->end(__('Go'));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $this->Paginator->sort(__('Date'), 'capture_date'); ?></th>
	<th class="from"><?php echo $this->Paginator->sort(__('From'), 'from_num'); ?></th>
        <th class="to"><?php echo $this->Paginator->sort(__('To'), 'to_num'); ?></th>
	<th class="number"><?php echo $this->Paginator->sort(__('Contents'), 'contents'); ?></th>
        <th class="date">Info</th>
</tr>
<?php foreach ($mms as $mm): ?>
<?php if ($mm['Mm']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $mm['Mm']['capture_date']; ?></td>
        <td><?php echo $mm['Mm']['from_num']; ?></td>
        <td><?php echo $mm['Mm']['to_num']; ?></td>
	<td><?php echo $this->Html->link($mm['Mm']['contents'],'/mms/view/' . $mm['Mm']['id']); ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/mms/info/<?php echo $mm['Mm']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a><div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/' . $mm['Mm']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $mm['Mm']['capture_date']; ?></b></td>
        <td><b><?php echo $mm['Mm']['from_num']; ?></b></td>
        <td><b><?php echo $mm['Mm']['to_num']; ?></b></td>
	<td><b><?php echo $this->Html->link($mm['Mm']['contents'],'/mms/view/' . $mm['Mm']['id']); ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/mms/info/<?php echo $mm['Mm']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a></b><div class="ipcap"><b><?php echo $this->Html->link('pcap', 'pcap/' . $mm['Mm']['id']); ?></b></div></td>
  </tr>
<?php endif ?>
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
