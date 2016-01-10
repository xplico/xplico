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

<?php echo $form->create('Search', array( 'url' => array('controller' => 'fbuchats', 'action' => 'chats')));
      echo $form->input('label', array('type'=>'text','size' => '40','maxlength'=>'40', 'label'=> __('Search:', true), 'default' => $srchd));
      echo $form->end(__('Go', true));
 ?>
</div>

 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="subject"><?php echo $paginator->sort(__('User', true), 'username'); ?></th>
	<th class="subject"><?php echo $paginator->sort(__('Friend', true), 'friend'); ?></th>
	<th class="subject"><?php echo $paginator->sort(__('Duration [hh:mm:ss]', true), 'duration'); ?></th>
	<th class="size"><?php echo $paginator->sort(__('Size', true), 'data_size'); ?></th>
        <th class="info"><?php __('Info'); ?></th>
 </tr>
 <?php foreach ($chats as $chat): ?>
  <?php $h = (int)($chat['Fbchat']['duration']/3600);
        $m = (int)($chat['Fbchat']['duration']/60 - $h*60);
        $s = $chat['Fbchat']['duration']%60;
        $friend = '<script type="text/javascript"> var txt="'.$chat['Fbchat']['friend'].'"; document.write(txt); </script>';
   ?>
 <?php if ($chat['Fbchat']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $chat['Fbchat']['capture_date']; ?></td>
	<td><script type="text/javascript"> var txt="<?php echo $chat['Fbchat']['username']; ?>"; document.write(txt); </script></td>
	<td><a href="#" onclick="popupVetrina('/fbuchats/view/<?php echo $chat['Fbchat']['id']; ?>','scrollbar=auto'); return false"><?php echo $friend; ?></a></td>
	<td><?php echo $h.":".$m.":".$s; ?></td>
	<td><?php echo $chat['Fbchat']['data_size']; ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/fbuchats/info/<?php echo $chat['Fbchat']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $chat['Fbchat']['id']); ?></div></td>
  </tr>
 <?php else : ?>
  <tr>
        <td><b><?php echo $chat['Fbchat']['capture_date']; ?></b></td>
        <td><b><script type="text/javascript"> var txt="<?php echo $chat['Fbchat']['username']; ?>"; document.write(txt); </script></b></td>
        <td><b><a href="#" onclick="popupVetrina('/fbuchats/view/<?php echo $chat['Fbchat']['id']; ?>','scrollbar=auto'); return false"><?php echo $friend; ?></a></b></td>
        <td><b><?php echo $h.":".$m.":".$s; ?></b></td>
        <td><b><?php echo $chat['Fbchat']['data_size']; ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/fbuchats/info/<?php echo $chat['Fbchat']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $chat['Fbchat']['id']); ?></div></b></td>
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
