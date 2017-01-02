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
<h2> <?php __('Email to'); echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mailObj['to']))?></h2>

<div id="messageframe">
<table class="headers-table" summary="Message headers" cellpadding="2" cellspacing="0">

<tbody>
<tr>
<td class="header-title"><?php __('Subject:'); ?></td>
<?php if (isset($mailObj['Subject'])): ?>
<?php if (strpos($email['Email']['subject'], '=?') != 0): ?>
<td class="subject"><?php echo htmlentities($mailObj['Subject']); ?></td>
<?php else: ?>
<td class="subject"><?php echo $mailObj['Subject']; ?></td>
<?php endif; ?>
<?php else: ?>
<td class="subject"></td>
<?php endif; ?>
<td class="header-title"><?php __('Relevance:'); ?></td>
<td class="date pinfo">
	<?php echo $this->Form->create('Email', array('url' => array ('action' => 'view')));?>
    <?php echo $this->Form->input('relevance', array('options' => $relevanceoptions, 'value' => $email['Email']['relevance'], 'label' => __('Choose relevance'), 'empty' => __('None')));     ?>
</td>
</tr>
<tr>
<td class="header-title"><?php __('Sender:'); ?></td>
<td class="from"><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mailObj['from']))?></td>
<td class="header-title" rowspan="7"><?php __('Comments'); ?></td>
<td class="date pinfo" rowspan="7">
    <?php echo $this->Form->input('comments', array ('label' => false, 'rows' => '5', 'cols' => '47', 'maxlength'=>'3000')       );        ?>
	<?php echo $this->Form->end(__('Save', true));?>
</td>
</tr>
<tr>
<td class="header-title"><?php __('Recipient:'); ?></td>
<td class="to"><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $mailObj['to']))?></td>
</tr>
<tr>
<td class="header-title"><?php __('Date:'); ?></td>
<td class="date"><?php echo $mailObj['Date']?></td>
</tr>
<tr>
<td class="header-title"><?php __('Username:'); ?></td>
<td class="date"><?php echo $email['Email']['username']?></td>
</tr>
<tr>
<td class="header-title"><?php __('Password:'); ?></td>
<td class="date"><?php echo $email['Email']['password']?></td>
</tr>
<tr>
<td class="header-title"><?php __('EML file:'); ?></td>
<td class="date"><?php echo $this->Html->link('email.eml', '/emails/eml') ?></td>
</tr>
<tr>
<td class="header-title"><?php __('Info:'); ?></td>
<td class="date pinfo"><a href="#" onclick="popupVetrina('/emails/info','scrollbar=auto'); return false"><?php __('info.xml'); ?></a><div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/'); ?></div></td>
</tr>
</tbody></table>
<?php if ($mailObj['Type'] == 'html') : ?>
<!--[if IE]>
<object class="html" classid="clsid:25336920-03F9-11CF-8FD0-00AA00686F13" data="some.html">
<p>backup content</p>
</object>
<![endif]-->
<!--[if !IE]> <-->
<object class="html" type="text/html" data="/emails/content/<?php echo strrchr($mailObj['DataFile'], '/')?>">
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
  <?php $i = 1; foreach($mailObj['Attachments'] as $attachment) : ?>
    <tr>
    <td class="header-title"><?php __('Attached'); echo ' '.$attachment['Type'] ?></td>
    <?php if (isset($attachment['FileName'])) : ?>
    <?php if (strpos($attachment['FileName'], '=?') != 0): ?>
    <td class="date"><?php echo $this->Html->link(htmlentities($attachment['FileName']), '/emails/content'.strrchr($attachment['DataFile'], '/')) ?></td>
    <?php else: ?>
    <td class="date"><?php echo $this->Html->link($attachment['FileName'], '/emails/content'.strrchr($attachment['DataFile'], '/')) ?></td>
    <?php endif; ?>
    <?php elseif (isset($attachment['Description'])) : ?>
    <td class="date"><?php echo $this->Html->link($attachment['Description'], '/emails/content'.strrchr($attachment['DataFile'], '/')) ?></td>
    <?php endif; ?>
    </tr>
  <?php endforeach; ?>
  </tbody></table>
<?php endif; ?>
</div>
</div>
