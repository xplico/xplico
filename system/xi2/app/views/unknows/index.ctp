<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<script language="JavaScript">
    function popupVetrina(whatopen) {
      newWindow = window.open(whatopen, 'popup_vetrina', 'width=620,height=550,scrollbars=yes,toolbar=no,resizable=yes,menubar=no');
      return false;
    }
</script>
<div class="generic">
<div class="search">


<center>
<?php echo $form->create('Unknows', array( 'url' => array('controller' => 'unknows', 'action' => 'index')));
      echo $form->input('search',  array( 'type'=>'text','size' => '40', 'label' => __('Search', true), 'default' => $srchd));
echo $form->end(__('Go', true));
?>
</center>
</div>
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th><?php echo $paginator->sort(__('Destination', true), 'dst'); ?></th>
        <th class="size"><?php echo $paginator->sort(__('Port', true), 'dst_port'); ?></th>
        <th class="date"><?php echo $paginator->sort(__('Protocol', true), 'l7prot'); ?></th>
        <th class="date"><?php echo $paginator->sort(__('Duration [s]', true), 'duration'); ?></th>
	<th class="date"><?php echo $paginator->sort(__('Size [byte]', true), 'size'); ?></th>
        <th class="info"><?php __('Info'); ?></th>
 </tr>
 <?php foreach ($unknows as $unknow): ?>
 <?php if ($unknow['Unknow']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $unknow['Unknow']['capture_date']; ?></td>
        <?php if ($unknow['Unknow']['file_path'] != 'None'): ?>
          <td><?php echo $html->link($unknow['Unknow']['dst'],'/unknows/file/' . $unknow['Unknow']['id']); ?></td>
        <?php else : ?>
          <td><?php echo $unknow['Unknow']['dst']; ?></td>
        <?php endif ?>
        <td><?php echo $unknow['Unknow']['dst_port']; ?></td>
        <td><?php echo $unknow['Unknow']['l7prot']; ?></td>
	<td><?php echo $unknow['Unknow']['duration']; ?></td>
	<td><?php echo $unknow['Unknow']['size']; ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/unknows/info/<?php echo $unknow['Unknow']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $unknow['Unknow']['id']); ?></div></td>
  </tr>
 <?php else : ?>
  <tr>
	<td><b><?php echo $unknow['Unknow']['capture_date']; ?></b></td>
        <?php if ($unknow['Unknow']['file_path'] != 'None'): ?>
          <td><b><?php echo $html->link($unknow['Unknow']['dst'],'/unknows/file/' . $unknow['Unknow']['id']); ?></b></td>
        <?php else : ?>
          <td><b><?php echo $unknow['Unknow']['dst']; ?></b></td>
        <?php endif ?>
	<td><b><?php echo $unknow['Unknow']['dst_port']; ?></b></td>
	<td><b><?php echo $unknow['Unknow']['l7prot']; ?></b></td>
	<td><b><?php echo $unknow['Unknow']['duration']; ?></b></td>
	<td><b><?php echo $unknow['Unknow']['size']; ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/unknows/info/<?php echo $unknow['Unknow']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $unknow['Unknow']['id']); ?></div></b></td>
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
