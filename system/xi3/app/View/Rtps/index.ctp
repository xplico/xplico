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
<?php echo $this->Form->create('Search',array( 'url' => array('controller' => 'rtps', 'action' => 'index')));
      echo $this->Form->input('label', array('type'=>'text','size' => '40', 'label'=> __('Search:'), 'default' => $srchd));
      echo $this->Form->end(__('Go'));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $this->Paginator->sort(__('Date'), 'capture_date'); ?></th>
	<th class="from"><?php echo $this->Paginator->sort(__('From'), 'from_addr'); ?></th>
        <th class="to"><?php echo $this->Paginator->sort(__('To'), 'to_addr'); ?></th>
	<th class="number"><?php echo $this->Paginator->sort(__('Duration'), 'duration'); ?></th>
        <th class="date"><?php echo __('Info'); ?></th>
</tr>
<?php foreach ($rtps as $rtp): ?>
<?php
 /* time in HH:MM:SS */
 $h = (int)($rtp['Rtp']['duration']/3600);
 $m = (int)(($rtp['Rtp']['duration']-3600*$h)/60);
 $s = $rtp['Rtp']['duration'] - 3600*$h - 60*$m;
 $hms=''.$h.':'.$m.':'.$s;
?>
<?php if ($rtp['Rtp']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $rtp['Rtp']['capture_date']; ?></td>
        <td><?php echo $rtp['Rtp']['from_addr']; ?></td>
        <td><?php echo $rtp['Rtp']['to_addr']; ?></td>
	<td><?php echo $this->Html->link($hms,'/rtps/view/' . $rtp['Rtp']['id']); ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/rtps/info/<?php echo $rtp['Rtp']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a><div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/' . $rtp['Rtp']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $rtp['Rtp']['capture_date']; ?></b></td>
        <td><b><?php echo $rtp['Rtp']['from_addr']; ?></b></td>
        <td><b><?php echo $rtp['Rtp']['to_addr']; ?></b></td>
	<td><b><?php echo $this->Html->link($hms,'/rtps/view/' . $rtp['Rtp']['id']); ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/rtps/info/<?php echo $rtp['Rtp']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a></b><div class="ipcap"><b><?php echo $this->Html->link('pcap', 'pcap/' . $rtp['Rtp']['id']); ?></b></div></td>
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
