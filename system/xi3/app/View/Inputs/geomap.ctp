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
<div class="sols">
<div class="inputs">
<h2><?php echo __('Geographical and temporal representation'); ?></h2>
<table cellspacing="0">
<tr>
	<th><?php echo __('Pcap file'); ?></th>
	<th><?php echo __('GeoMap file'); ?></th>
</tr>
<?php foreach ($inputs as $input): ?>
<tr>
	<td><?php echo $input['Input']['filename']; ?></td>
        <td><b><A href="#" onclick="popupVetrina('/inputs/kml_file/<?php echo $input['Input']['id']; ?>','scrollbar=auto'); return false"><?php echo $input['Input']['filename'] . '.kml'; ?></A></b></td>
</tr>

<?php endforeach; ?>
</table>
</div>
</div>
