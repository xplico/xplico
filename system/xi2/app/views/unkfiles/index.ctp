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
<div class="search">


<center>
<?php echo $form->create('Unkfiles', array( 'url' => array('controller' => 'unkfiles', 'action' => 'index')));
      echo $form->input('search',  array( 'type'=>'text','size' => '40', 'label' => __('Search', true), 'default' => $srchd));
echo $form->end(__('Go', true));
?>
</center>
</div>
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="date"><?php echo $paginator->sort(__('File', true), 'file_name'); ?></th>
	<th class="size"><?php echo $paginator->sort(__('Type', true), 'file_type'); ?></th>
	<th class="size"><?php echo $paginator->sort(__('Size', true), 'fsize'); ?></th>
	<th class="info"><?php __('Info'); ?></th>
 </tr>
 <?php foreach ($unkfiles as $unkfile): ?>
 <?php if ($unkfile['Unkfile']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $unkfile['Unkfile']['capture_date']; ?></td>
	<td><?php echo $html->link($unkfile['Unkfile']['file_name'],'/unkfiles/bin/' . $unkfile['Unkfile']['id']); ?></td>
	<td><?php echo $unkfile['Unkfile']['file_type']; ?></td>
	<td><?php echo $unkfile['Unkfile']['fsize']; ?></td>
  </tr>
 <?php else : ?>
  <tr>
	<td><b><?php echo $unkfile['Unkfile']['capture_date']; ?></b></td>
	<td><b><?php echo $html->link($unkfile['Unkfile']['file_name'],'/unkfiles/bin/' . $unkfile['Unkfile']['id']); ?></b></td>
	<td><b><?php echo $unkfile['Unkfile']['file_type']; ?></b></td>
	<td><b><?php echo $unkfile['Unkfile']['fsize']; ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/unkfiles/info/<?php echo $unkfile['Unkfile']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a></b><div class="ipcap"><b><?php echo $html->link('pcap', 'pcap/' . $unkfile['Unkfile']['id']); ?></b></div></td>
  </tr>
 <?php endif ?>
<?php endforeach; ?>
</table>
<table id="listpage" summary="Message list" cellspacing="0">
<tr>
	<th class="next"><?php echo $paginator->prev(__('Previous', true), array(), null, array('class'=>'disabled')); ?></th>
       	<th><?php echo $paginator->numbers(); echo '<br/>'.$paginator->counter(); ?></th>
	<th class="next"><?php echo $paginator->next(__('Next', true), array(), null, array('class' => 'disabled')); ?></th>
</tr>
</table>
</div>
