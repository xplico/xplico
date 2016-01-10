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
<?php echo $form->create('Search',array( 'url' => array('controller' => 'mms', 'action' => 'index')));
      echo $form->input('label', array('type'=>'text','size' => '40', 'label'=> __('Search:', true), 'default' => $srchd));
      echo $form->end(__('Go', true));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="from"><?php echo $paginator->sort(__('From', true), 'from_num'); ?></th>
        <th class="to"><?php echo $paginator->sort(__('To', true), 'to_num'); ?></th>
	<th class="number"><?php echo $paginator->sort(__('Contents', true), 'contents'); ?></th>
        <th class="date">Info</th>
</tr>
<?php foreach ($mms as $mm): ?>
<?php if ($mm['Mm']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $mm['Mm']['capture_date']; ?></td>
        <td><?php echo $mm['Mm']['from_num']; ?></td>
        <td><?php echo $mm['Mm']['to_num']; ?></td>
	<td><?php echo $html->link($mm['Mm']['contents'],'/mms/view/' . $mm['Mm']['id']); ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/mms/info/<?php echo $mm['Mm']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a><div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $mm['Mm']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $mm['Mm']['capture_date']; ?></b></td>
        <td><b><?php echo $mm['Mm']['from_num']; ?></b></td>
        <td><b><?php echo $mm['Mm']['to_num']; ?></b></td>
	<td><b><?php echo $html->link($mm['Mm']['contents'],'/mms/view/' . $mm['Mm']['id']); ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/mms/info/<?php echo $mm['Mm']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a></b><div class="ipcap"><b><?php echo $html->link('pcap', 'pcap/' . $mm['Mm']['id']); ?></b></div></td>
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
