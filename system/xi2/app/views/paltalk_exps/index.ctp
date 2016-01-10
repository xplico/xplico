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
<?php echo $form->create('Search',array( 'url' => array('controller' => 'paltalk_exps', 'action' => 'index')));
      echo $form->input('label', array('type'=>'text','size' => '40', 'label' => __('Search:', true), 'default' => $srchd));
     echo $form->end(__('Go', true));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="date"><?php echo $paginator->sort(__('End', true), 'end_date'); ?></th>
	<th class="from"><?php echo $paginator->sort(__('User-Nick name', true), 'user_nick'); ?></th>
	<th class="info"><?php __('Info'); ?></th>

</tr>
<?php foreach ($paltalk_exps as $paltalk): ?>
<?php if ($paltalk['Paltalk_exp']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $paltalk['Paltalk_exp']['capture_date']; ?></td>
	<td><?php echo $paltalk['Paltalk_exp']['end_date']; ?></td>
        <td><a href="#" onclick="popupVetrina('/paltalk_exps/chat/<?php echo $paltalk['Paltalk_exp']['id']; ?>','scrollbar=auto'); return false"><?php echo $paltalk['Paltalk_exp']['user_nick']; ?></a></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/paltalk_exps/info/<?php echo $paltalk['Paltalk_exp']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $paltalk['Paltalk_exp']['id']); ?></div></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $paltalk['Paltalk_exp']['capture_date']; ?></b></td>
        <td><b><?php echo $paltalk['Paltalk_exp']['end_date']; ?></b></td>
        <td><b><a href="#" onclick="popupVetrina('/paltalk_exps/chat/<?php echo $paltalk['Paltalk_exp']['id']; ?>','scrollbar=auto'); return false"><?php echo $paltalk['Paltalk_exp']['user_nick']; ?></a></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/paltalk_exps/info/<?php echo $paltalk['Paltalk_exp']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $paltalk['Paltalk_exp']['id']); ?></div></b></td>
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
