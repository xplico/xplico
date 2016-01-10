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
<table id="messagelist" cellpadding="2" cellspacing="0">
<tr>
<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
<th><?php echo $paginator->sort(__('Url', true), 'url'); ?></th>
<th class="size"><?php echo $paginator->sort(__('Size', true), 'rs_bd_size'); ?></th>
<th class="info"><?php __('Info'); ?></th>
</tr>
<?php foreach ($feeds_xml as $feed):?>

<?php if ($feed['Feed_xml']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $feed['feed_xml']['capture_date']; ?></td>
        <td class="url"><a href="#" onclick="popupVetrina('/feeds/xml/<?php echo $feed['Feed_xml']['id']; ?>','scrollbar=auto'); return false"><?php echo $feed['Feed_xml']['url']; ?></a></td>
        <td><?php echo $feed['Feed_xml']['rs_bd_size']; ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/feeds/info/<?php echo $feed['Feed_xml']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $feed['Feed_xml']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $feed['Feed_xml']['capture_date']; ?></b></td>
        <td class="url"><b><a href="#" onclick="popupVetrina('/feeds/xml/<?php echo $feed['Feed_xml']['id']; ?>','scrollbar=auto'); return false"><?php echo $feed['Feed_xml']['url']; ?></a></b></td>
        <td><b><?php echo $feed['Feed_xml']['rs_bd_size']; ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/feeds/info/<?php echo $feed['Feed_xml']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a></b> <div class="ipcap"><b><?php echo $html->link('pcap', 'pcap/' . $feed['Feed_xml']['id']); ?></b></div></td>
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
