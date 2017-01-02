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
<?php echo $this->Form->create('Unknows', array( 'url' => array('controller' => 'unknows', 'action' => 'index')));
      echo $this->Form->input('search',  array( 'type'=>'text','size' => '40', 'label' => __('Search'), 'default' => $srchd));
echo $this->Form->end(__('Go'));
?>
</center>
</div>
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $this->Paginator->sort(__('Date'), 'capture_date'); ?></th>
	<th><?php echo $this->Paginator->sort(__('Destination'), 'dst'); ?></th>
        <th class="size"><?php echo $this->Paginator->sort(__('Port'), 'dst_port'); ?></th>
        <th class="date"><?php echo $this->Paginator->sort(__('Protocol'), 'l7prot'); ?></th>
        <th class="date"><?php echo $this->Paginator->sort(__('Duration [s]'), 'duration'); ?></th>
	<th class="date"><?php echo $this->Paginator->sort(__('Size [byte]'), 'size'); ?></th>
        <th class="info"><?php echo __('Info'); ?></th>
 </tr>
 <?php foreach ($unknows as $unknow): ?>
 <?php if ($unknow['Unknow']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $unknow['Unknow']['capture_date']; ?></td>
        <?php if ($unknow['Unknow']['file_path'] != 'None'): ?>
          <td><?php echo $this->Html->link($unknow['Unknow']['dst'],'/unknows/file/' . $unknow['Unknow']['id']); ?></td>
        <?php else : ?>
          <td><?php echo $unknow['Unknow']['dst']; ?></td>
        <?php endif ?>
        <td><?php echo $unknow['Unknow']['dst_port']; ?></td>
        <td><?php echo $unknow['Unknow']['l7prot']; ?></td>
	<td><?php echo $unknow['Unknow']['duration']; ?></td>
	<td><?php echo $unknow['Unknow']['size']; ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/unknows/info/<?php echo $unknow['Unknow']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a> <div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/' . $unknow['Unknow']['id']); ?></div></td>
  </tr>
 <?php else : ?>
  <tr>
	<td><b><?php echo $unknow['Unknow']['capture_date']; ?></b></td>
        <?php if ($unknow['Unknow']['file_path'] != 'None'): ?>
          <td><b><?php echo $this->Html->link($unknow['Unknow']['dst'],'/unknows/file/' . $unknow['Unknow']['id']); ?></b></td>
        <?php else : ?>
          <td><b><?php echo $unknow['Unknow']['dst']; ?></b></td>
        <?php endif ?>
	<td><b><?php echo $unknow['Unknow']['dst_port']; ?></b></td>
	<td><b><?php echo $unknow['Unknow']['l7prot']; ?></b></td>
	<td><b><?php echo $unknow['Unknow']['duration']; ?></b></td>
	<td><b><?php echo $unknow['Unknow']['size']; ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/unknows/info/<?php echo $unknow['Unknow']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a> <div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/' . $unknow['Unknow']['id']); ?></div></b></td>
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
