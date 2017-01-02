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
<h2><?php echo __('Telnet to'); ?> <?php echo $telnet['Telnet']['hostname']; ?></h2>

<div id="messageframe">
<table class="headers-table" summary="Message headers" cellpadding="2" cellspacing="0">

<tbody>
<tr>
<td class="header-title"><?php echo __('Host:'); ?></td>
<td class="subject"><?php echo $telnet['Telnet']['hostname']; ?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('Username:'); ?></td>
<td class="date"><?php echo $telnet['Telnet']['username']; ?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('Password:'); ?></td>
<td class="date"><?php echo $telnet['Telnet']['password']; ?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('Info:'); ?></td>
<td class="date pinfo"><a href="#" onclick="popupVetrina('/telnets/info','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a><div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/'); ?></div></td>
</tr>
</tbody></table>

<div class="centered">
<textarea cols="81" rows="16" readonly="readonly" ><?php echo file_get_contents($telnet['Telnet']['cmd']); ?></textarea>
</div>
</div>
</div>