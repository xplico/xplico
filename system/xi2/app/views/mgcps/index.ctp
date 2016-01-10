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
<?php echo $form->create('Search',array( 'url' => array('controller' => 'mgcps', 'action' => 'index')));
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
<?php foreach ($mgcps as $mgcp): ?>
<?php
 /* time in HH:MM:SS */
 $h = (int)($mgcp['Mgcp']['duration']/3600);
 $m = (int)(($mgcp['Mgcp']['duration']-3600*$h)/60);
 $s = $mgcp['Mgcp']['duration'] - 3600*$h - 60*$m;
 $hms=''.$h.':'.$m.':'.$s;
?>
<?php if ($mgcp['Mgcp']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $mgcp['Mgcp']['capture_date']; ?></td>
        <td><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mgcp['Mgcp']['from_addr'])); ?> </td>
        <td><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mgcp['Mgcp']['to_addr'])); ?></td>
	<td><?php echo $html->link($hms,'/mgcps/view/' . $mgcp['Mgcp']['id']); ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/mgcps/info/<?php echo $mgcp['Mgcp']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a><div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $mgcp['Mgcp']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $mgcp['Mgcp']['capture_date']; ?></b></td>
        <td><b><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mgcp['Mgcp']['from_addr'])); ?></b></td>
        <td><b><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mgcp['Mgcp']['to_addr'])); ?></b></td>
	<td><b><?php echo $html->link($hms,'/mgcps/view/' . $mgcp['Mgcp']['id']); ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/mgcps/info/<?php echo $mgcp['Mgcp']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a></b><div class="ipcap"><b><?php echo $html->link('pcap', 'pcap/' . $mgcp['Mgcp']['id']); ?></b></div></td>
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
