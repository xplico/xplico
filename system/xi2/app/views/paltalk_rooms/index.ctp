<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<script language="JavaScript">
    function popupVetrina(whatopen) {
      newWindow = window.open(whatopen, 'popup_vetrina', 'width=620,height=550,scrollbars=yes,toolbar=no,resizable=yes,menubar=no');
      return false;
    }
</script>

<div class="generic">
<div class="search">
<center>
<?php echo $form->create('Search',array( 'url' => array('controller' => 'paltalk_rooms', 'action' => 'index')));
      echo $form->input('label', array('type'=>'text','size' => '40', 'label' => __('Search:', true), 'default' => $srchd));
     echo $form->end(__('Go', true));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="date"><?php echo $paginator->sort(__('End', true), 'end_date'); ?></th>
	<th class="from"><?php echo $paginator->sort(__('Room name', true), 'room'); ?></th>
        <th class="date"><?php echo $paginator->sort(__('Duration', true), 'duration'); ?></th>
	<th class="info"><?php __('Info'); ?></th>

</tr>
<?php foreach ($paltalk_rooms as $paltalk): 
   $dh = (int)($paltalk['Paltalk_room']['duration']/3600);
   $dm = (int)(($paltalk['Paltalk_room']['duration'] - $dh*3600)/60);
   $ds = (int)(($paltalk['Paltalk_room']['duration'] - $dh*3600) - $dm*60);
   $duration = $dh.':'.$dm.':'.$ds;
?>
<?php if ($paltalk['Paltalk_room']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $paltalk['Paltalk_room']['capture_date']; ?></td>
	<td><?php echo $paltalk['Paltalk_room']['end_date']; ?></td>
        <td><a href="#" onclick="popupVetrina('/paltalk_rooms/room/<?php echo $paltalk['Paltalk_room']['id']; ?>','scrollbar=auto'); return false"><?php echo $paltalk['Paltalk_room']['room']; ?></a></td>
        <td><?php echo $duration; ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/paltalk_rooms/info/<?php echo $paltalk['Paltalk_room']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $paltalk['Paltalk_room']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $paltalk['Paltalk_room']['capture_date']; ?></b></td>
        <td><b><?php echo $paltalk['Paltalk_room']['end_date']; ?></b></td>
        <td><b><a href="#" onclick="popupVetrina('/paltalk_rooms/room/<?php echo $paltalk['Paltalk_room']['id']; ?>','scrollbar=auto'); return false"><?php echo $paltalk['Paltalk_room']['room']; ?></a></b></td>
        <td><b><?php echo $duration; ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/paltalk_rooms/info/<?php echo $paltalk['Paltalk_room']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $paltalk['Paltalk_room']['id']); ?></div></b></td>
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
