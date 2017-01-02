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
<h2><?php echo __('Article from'); ?> <?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mailObj['from']))?></h2>

<div id="messageframe">
<table class="headers-table" summary="Message headers" cellpadding="2" cellspacing="0">

<tbody><tr>
<td class="header-title"><?php echo __('Subject:'); ?></td>
<td class="subject"><?php echo $mailObj['Subject']?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('Sender:'); ?></td>
<td class="from"><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mailObj['from'])) ?> </td>
</tr>
<tr>
<td class="header-title"><?php echo __('Recipient:'); ?></td>
<td class="to"><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mailObj['to'])) ?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('Date:'); ?></td>
<td class="date"><?php echo $mailObj['Date']?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('EML file:'); ?></td>
<td class="date"><?php echo $this->Html->link('article.eml', '/nntp_groups/eml') ?></td>
</tr>
<tr>
<td class="header-title"><?php echo __('Info:'); ?></td>
<td class="date pinfo"><a href="#" onclick="popupVetrina('/nntp_groups/info','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a><div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/'); ?></div></td>
</tr>
</tbody></table>
<?php if ($mailObj['Type'] == 'html') : ?>
<!--[if IE]>
<object class="html" classid="clsid:25336920-03F9-11CF-8FD0-00AA00686F13" data="some.html">
<p>backup content</p>
</object>
<![endif]-->
<!--[if !IE]> <-->
<object class="html" type="text/html" data="/nntp_groups/content/<?php echo strrchr($mailObj['DataFile'], '/')?>">
<p>backup content</p>
</object>
<?php elseif ($mailObj['Type'] == 'text') : ?>
<div class="centered">
<textarea cols="81" rows="10" readonly="readonly" ><?php echo file_get_contents($mailObj['DataFile']); ?></textarea>
</div>
<?php endif; ?>
<?php if (isset($mailObj['Attachments'])) : ?>
  <table class="headers-table" summary="Message headers" cellpadding="2" cellspacing="0">
  <tbody>
  <?php foreach($mailObj['Attachments'] as $attachment) : ?>
    <tr>
    <td class="header-title">Attached <?php echo $attachment['Type'] ?></td>
    <?php if (isset($attachment['FileName'])) : ?>
    <td class="date"><?php echo $this->Html->link($attachment['FileName'], '/nntp_groups/content'.strrchr($attachment['DataFile'], '/')) ?></td>
    <?php elseif (isset($attachment['Description'])) : ?>
    <td class="date"><?php echo $this->Html->link($attachment['Description'], '/nntp_groups/content'.strrchr($attachment['DataFile'], '/')) ?></td>
    <?php endif; ?>
    </tr>
  <?php endforeach; ?>
  </tbody></table>
<?php endif; ?>
</div>
</div>