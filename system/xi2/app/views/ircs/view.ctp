<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<SCRIPT language="JavaScript">
    function popupVetrina(whatopen) {
      newWindow = window.open(whatopen, 'popup_vetrina', 'width=520,height=550,scrollbars=yes,toolbar=no,resizable=yes,menubar=no');
      return false;
    }
</SCRIPT>

<div class="generic">
<div id="messageframe">
<table class="headers-table" summary="Message headers" cellpadding="2" cellspacing="0">

<tbody>
<tr>
<td class="header-title"><?php __('Url:'); ?>&nbsp;</td>
<td class="subject" width="90%"><?php echo $irc['Irc']['url']?></td>
</tr>
<tr>
<td class="header-title"><?php __('Commands:'); ?>&nbsp;</td>
<td class="date" width="90%"><A href="#" onclick="popupVetrina('/ircs/cmd','scrollbar=auto'); return false">cmd.txt</A></td>
</tr>
<tr>
<td class="header-title"><?php __('Info:'); ?>&nbsp;</td>
<td class="date pinfo" width="90%"><a href="#" onclick="popupVetrina('/ircs/info','scrollbar=auto'); return false">info.xml</a><div class="ipcap"><?php echo $html->link('pcap', 'pcap/'); ?></div></td>
</tr>
</tbody></table>

<table id="messagelist" cellpadding="2" cellspacing="0">
<tr>
<th><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
<th><?php echo $paginator->sort(__('Channel', true), 'channel'); ?></th>
<th><?php echo $paginator->sort(__('End', true), 'end_date'); ?></th>
<th>Info</th>
</tr>
<?php foreach ($irc_channel as $data_file): ?>
<tr>
<td><?php echo $data_file['Irc_channel']['capture_date']; ?></td>
<td><a href="#" onclick="popupVetrina('/ircs/channel/<?php echo $data_file['Irc_channel']['id']; ?>','scrollbar=auto'); return false"><?php echo $data_file['Irc_channel']['channel']; ?></a></td>
<td><?php echo $data_file['Irc_channel']['end_date']; ?></td>
<td class="pinfo"><a href="#" onclick="popupVetrina('/ircs/info_channel/<?php echo $data_file['Irc_channel']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a><div class="ipcap"><?php echo $html->link('pcap', 'pcap/'.$data_file['Irc_channel']['id']); ?></div></td>
</tr>
<?php endforeach; ?>
</table>
</div>
<table id="listpage" summary="Message list" cellspacing="0">
<tr>
	<th class="next"><?php echo $paginator->prev(__('Previous', true), array(), null, array('class'=>'disabled')); ?></th>
       	<th><?php echo $paginator->numbers(); echo '<br/>'.$paginator->counter(); ?></th>
	<th class="next"><?php echo $paginator->next(__('Next', true), array(), null, array('class' => 'disabled')); ?></th>
</tr>
</table>
</div>