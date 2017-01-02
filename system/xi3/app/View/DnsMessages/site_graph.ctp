<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<script type="text/javascript">
  swfobject.embedSWF("/files/open-flash-chart.swf", "my_chart", "750", "380", "9.0.0",
      "expressInstall.swf",
      {"data-file":"/dns_messages/gsitedata"}
);
</script>
<script type="text/javascript">
  function go_gpage(id) { //funzione con il link alla pagina che si desidera raggiungere
    window.location.href = '<?php echo $dns_gpage_url?>';
  }
</script>
<div class="generic">
   <div class="graph">
   <div id="my_chart"></div>
   </div>
</div>
