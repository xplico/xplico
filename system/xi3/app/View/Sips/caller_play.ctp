<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="voip_flash">
<object codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=10,0,0,0" width="350" height="90" id="sound" align="middle">
        <param name="allowScriptAccess" value="sameDomain"></param>
        <param name="allowFullScreen" value="false"></param>
        <param name="movie" value="/files/xplico_voip.swf"></param>
        <param name="quality" value="high"></param>
        <param name="bgcolor" value="#380000"></param>
        <param name=FlashVars  value="audio_url=<?php echo '/sips/caller/'.$sip_id; ?>"></param>
        <embed src="/files/xplico_voip.swf" quality="high" bgcolor="#380000" width="350" height="90"  FlashVars="audio_url=<?php echo '/sips/caller/'.$sip_id; ?>" name="sound" align="middle" wmode="window" allowscriptaccess="sameDomain" allowfullscreen="false" type="application/x-shockwave-flash" pluginspage="http://www.adobe.com/go/getflashplayer_en"></embed>
</object>
</div>
