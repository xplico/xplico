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
<?php echo $form->create('Search',array( 'url' => array('controller' => 'msn_chats', 'action' => 'index')));
      echo $form->input('label', array('type'=>'text','size' => '40', 'label' => __('Search:', true), 'default' => $srchd));
     echo $form->end(__('Go', true));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="date"><?php echo $paginator->sort(__('End', true), 'end_date'); ?></th>
	<th class="from"><?php echo $paginator->sort(__('Chat', true), 'chat'); ?></th>
        <th class="date"><?php echo $paginator->sort(__('Duration', true), 'duration'); ?></th>
	<th class="info"><?php __('Info'); ?></th>
</tr>
<?php foreach ($msn_chats as $msn): 
   $dh = (int)($msn['Msn_chat']['duration']/3600);
   $dm = (int)(($msn['Msn_chat']['duration'] - $dh*3600)/60);
   $ds = (int)(($msn['Msn_chat']['duration'] - $dh*3600) - $dm*60);
   $duration = $dh.':'.$dm.':'.$ds;
?>
<?php if ($msn['Msn_chat']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $msn['Msn_chat']['capture_date']; ?></td>
	<td><?php echo $msn['Msn_chat']['end_date']; ?></td>
        <td><a href="#" onclick="popupVetrina('/msn_chats/chat/<?php echo $msn['Msn_chat']['id']; ?>','scrollbar=auto'); return false"><?php echo htmlentities($msn['Msn_chat']['chat']); ?></a></td>
        <td><?php echo $duration; ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/msn_chats/info/<?php echo $msn['Msn_chat']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $msn['Msn_chat']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $msn['Msn_chat']['capture_date']; ?></b></td>
        <td><b><?php echo $msn['Msn_chat']['end_date']; ?></b></td>
        <td><b><a href="#" onclick="popupVetrina('/msn_chats/chat/<?php echo $msn['Msn_chat']['id']; ?>','scrollbar=auto'); return false"><?php echo htmlentities($msn['Msn_chat']['chat']); ?></a></b></td>
        <td><b><?php echo $duration; ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/msn_chats/info/<?php echo $msn['Msn_chat']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $msn['Msn_chat']['id']); ?></div></b></td>
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
