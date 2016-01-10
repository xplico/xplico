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
<script language="JavaScript">
    function popupVoip(whatopen) {
      newWindow = window.open(whatopen, 'popup_vetrina', 'width=370,height=110,toolbar=no,resizable=no,menubar=no');
      return false;
    }
</script>

<div class="generic">
<div id="messageframe">
<table class="headers-table" summary="Message headers" cellpadding="2" cellspacing="0">
<tbody>
<tr>
<td class="header-title"><?php __('Date:'); ?>&nbsp;</td>
<td class="date" ><?php echo $mgcp['Mgcp']['capture_date']; ?></td><td></td>
</tr>
<tr>
<td class="header-title"><?php __('From:'); ?>&nbsp;</td>
<td class="from" ><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mgcp['Mgcp']['from_addr'])); ?></td><td><a href="#" onclick="popupVoip('/mgcps/caller_play/<?php echo $mgcp['Mgcp']['id']?>','scrollbar=auto'); return false"><?php __('play'); ?></a></td>
</tr>
<tr>
<td class="header-title"><?php __('To:'); ?>&nbsp;</td>
<td class="to" ><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mgcp['Mgcp']['to_addr'])); ?></td></td><td><a href="#" onclick="popupVoip('/mgcps/called_play/<?php echo $mgcp['Mgcp']['id']?>','scrollbar=auto'); return false"><?php __('play'); ?></a></td>
</tr>
<tr>
<td class="header-title"><?php __('Duration:'); ?>&nbsp;</td>
<?php
 /* time in HH:MM:SS */
 $h = (int)($mgcp['Mgcp']['duration']/3600);
 $m = (int)(($mgcp['Mgcp']['duration']-3600*$h)/60);
 $s = $mgcp['Mgcp']['duration'] - 3600*$h - 60*$m;
 $hms=''.$h.':'.$m.':'.$s;
?>
<td class="date" ><?php echo $hms; ?></td><td></td>
</tr>
<tr>
<td class="header-title"><?php __('Commands:'); ?>&nbsp;</td>
<td class="date" ><a href="#" onclick="popupVetrina('/mgcps/cmds/<?php echo $mgcp['Mgcp']['id']?>','scrollbar=auto'); return false">cmd.txt</a></td>
</tr>
<td class="header-title"><?php __('Info:'); ?>&nbsp;</td>
<td class="date pinfo" ><a href="#" onclick="popupVetrina('/mgcps/info/<?php echo $mgcp['Mgcp']['id']?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a><div class="ipcap"><?php echo $html->link('pcap', 'pcap/'); ?></div></td><td></td>
</tr>
</tbody></table>
</div>
<div class="voip_flash">
<object codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=10,0,0,0" width="800" height="220" id="sound" align="middle">
        <param name="allowScriptAccess" value="sameDomain"></param>
        <param name="allowFullScreen" value="false"></param>
        <param name="movie" value="/files/xplico_voip_mix.swf"></param>
        <param name="quality" value="high"></param>
        <param name="bgcolor" value="#380000"></param>
        <param name=FlashVars  value="audio_url=<?php echo '/mgcps/mix/'.$mgcp['Mgcp']['id']; ?>"></param>
        <embed src="/files/xplico_voip_mix.swf" quality="high" bgcolor="#380000" width="800" height="220"  FlashVars="audio_url=<?php echo '/mgcps/mix/'.$mgcp['Mgcp']['id']; ?>" name="sound" align="middle" wmode="window" allowscriptaccess="sameDomain" allowfullscreen="false" type="application/x-shockwave-flash" pluginspage="http://www.adobe.com/go/getflashplayer_en"></embed>
</object>
</div>

<div class="cline"> </div>
</div>
