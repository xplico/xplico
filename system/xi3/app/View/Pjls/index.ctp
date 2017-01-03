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
<h2><?php echo __('List printed file'); ?></h2>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $this->Paginator->sort('capture_date', __('Date')); ?></th>
	<th class="from"><?php echo $this->Paginator->sort('url', __('Url')); ?></th>
	<th class="size"><?php echo $this->Paginator->sort('pdf_size', __('Data Size')); ?></th>
	<th class="info"><?php echo __('Info'); ?></th>
</tr>
<?php foreach ($pjls as $pjl): ?>
<?php if ($pjl['Pjl']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $pjl['Pjl']['capture_date']; ?></td>
        <td><?php echo $this->Html->link($pjl['Pjl']['url'], 'view/' . $pjl['Pjl']['id']); ?></td>

	<td><?php echo $pjl['Pjl']['pdf_size']; ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/pjls/info/<?php echo $pjl['Pjl']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a><div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/' . $pjl['Pjl']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $pjl['Pjl']['capture_date']; ?></b></td>
        <td><b><?php echo $this->Html->link($pjl['Pjl']['url'], 'view/' . $pjl['Pjl']['id']); ?></b></td>
	<td><b><?php echo $pjl['Pjl']['pdf_size']; ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/pjls/info/<?php echo $pjl['Pjl']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a></b><div class="ipcap"><b><?php echo $this->Html->link('pcap', 'pcap/' . $pjl['Pjl']['id']); ?></b></div></td>
  </tr>
<?php endif ?>
<?php endforeach; ?>
</table>

<table id="listpage" summary="Message list" cellspacing="0">
<tr>
	<th class="next"><?php echo $this->Paginator->prev(__('Previous'), array(), null, array('class'=>'disabled')); ?></th>
       	<th><?php echo $this->Paginator->numbers(); echo '<br/>'.$this->Paginator->counter(); ?></th>
	<th class="next"><?php echo $this->Paginator->next(__('Next'), array(), null, array('class' => 'disabled')); ?></th>
</tr>
</table>
</div>
