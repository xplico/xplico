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
<table class="headers-table" summary="Message headers" cellpadding="2" cellspacing="0">

<tbody><tr>
<td class="header-title"><?php echo __('From:'); ?>&nbsp;</td>
<td class="subject" ><?php echo $mm['Mm']['from_num']?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('To:'); ?>&nbsp;</td>
<td class="date" ><?php echo $mm['Mm']['to_num']?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('Cc:'); ?>&nbsp;</td>
<td class="date" ><?php echo $mm['Mm']['cc_num']?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('Bcc:'); ?>&nbsp;</td>
<td class="date" ><?php echo $mm['Mm']['bcc_num']?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('Info:'); ?>&nbsp;</td>
<td class="date pinfo" ><a href="#" onclick="popupVetrina('/mms/info/<?php echo $mm['Mm']['id']?>','scrollbar=auto'); return false">info.xml</a><div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/'); ?></div></td>
</tr>
</tbody></table>

<table id="messagelist" cellpadding="2" cellspacing="0">
<tr>
<th><?php echo __('Content Type'); ?></th>
<th><?php echo __('File name'); ?></th>
<th><?php echo __('Size'); ?></th>
</tr>
<?php foreach ($mmscontent as $data_file): ?>
<tr>
<td><?php echo $data_file['Mmscontent']['content_type']; ?></td>
<td><A href="#" onclick="popupVetrina('/mms/data_file/<?php echo  $data_file['Mmscontent']['id']?>','scrollbar=auto'); return false"><?php echo  $data_file['Mmscontent']['filename']?></A>
<td><?php echo $data_file['Mmscontent']['file_size']; ?></td>
</tr>
<?php endforeach; ?>
</table>
<?php foreach ($mmscontent as $data_file): ?>
 <?php if (stristr($data_file['Mmscontent']['content_type'], "image") != null) : ?>
 <div class="centered">
   <img src=/mms/data_file/<?php echo  $data_file['Mmscontent']['id']?> />
 </div>
 <?php elseif(stristr($data_file['Mmscontent']['content_type'], "text") != null) : ?>
 <div class="centered">
   <textarea id="contenuto" cols="80" rows="2" style="text-align: left;" readonly="readonly"><?php echo file_get_contents($data_file['Mmscontent']['file_path']); ?>
   </textarea>
 </div>
 <?php endif; ?>
<?php endforeach; ?>
</div>
