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
<?php echo $form->create('Search',array( 'url' => array('controller' => 'rtps', 'action' => 'index')));
      echo $form->input('label', array('type'=>'text','size' => '40', 'label'=> __('Search:', true), 'default' => $srchd));
      echo $form->end(__('Go', true));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="from"><?php echo $paginator->sort(__('From', true), 'from_addr'); ?></th>
        <th class="to"><?php echo $paginator->sort(__('To', true), 'to_addr'); ?></th>
	<th class="number"><?php echo $paginator->sort(__('Duration', true), 'duration'); ?></th>
        <th class="date"><?php __('Info'); ?></th>
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
	<td><?php echo $html->link($hms,'/rtps/view/' . $rtp['Rtp']['id']); ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/rtps/info/<?php echo $rtp['Rtp']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a><div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $rtp['Rtp']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $rtp['Rtp']['capture_date']; ?></b></td>
        <td><b><?php echo $rtp['Rtp']['from_addr']; ?></b></td>
        <td><b><?php echo $rtp['Rtp']['to_addr']; ?></b></td>
	<td><b><?php echo $html->link($hms,'/rtps/view/' . $rtp['Rtp']['id']); ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/rtps/info/<?php echo $rtp['Rtp']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a></b><div class="ipcap"><b><?php echo $html->link('pcap', 'pcap/' . $rtp['Rtp']['id']); ?></b></div></td>
  </tr>
<?php endif ?>
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
