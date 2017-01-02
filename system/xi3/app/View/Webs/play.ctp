<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
	<a 
            href="<?php echo '/webs/resBody/'.$message['Web']['id']."?.flv"; ?>"
            style="display:block;width:400px;height:300px;margin:auto;"
            id="player"> 
        </a> 
        <script>
            flowplayer("player", "/files/flowplayer-3.2.2.swf");
        </script>
</div>
