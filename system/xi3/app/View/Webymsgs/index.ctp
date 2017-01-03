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

<?php echo $this->Form->create('Search', array( 'url' => array('controller' => 'webymsgs', 'action' => 'chats')));
      echo $this->Form->input('label', array('type'=>'text','size' => '40','maxlength'=>'40', 'label'=> __('Search:'), 'default' => $srchd));
      echo $this->Form->end(__('Go'));
 ?>
</div>

 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $this->Paginator->sort('capture_date', __('Date')); ?></th>
	<th class="subject"><?php echo $this->Paginator->sort('user', __('User')); ?></th>
	<th class="subject"><?php echo $this->Paginator->sort('friend', __('Friend')); ?></th>
	<th class="subject"><?php echo $this->Paginator->sort('duration', __('Duration [hh:mm:ss]')); ?></th>
	<th class="size"><?php echo $this->Paginator->sort('data_size', __('Size')); ?></th>
    <th class="info"><?php echo __('Info'); ?></th>
 </tr>
 <?php foreach ($chats as $chat): ?>
  <?php $h = (int)($chat['Webymsg']['duration']/3600);
        $m = (int)($chat['Webymsg']['duration']/60 - $h*60);
        $s = $chat['Webymsg']['duration']%60;
        $friend = '<script type="text/javascript"> var txt="'.$chat['Webymsg']['friend'].'"; document.write(txt); </script>';
   ?>
 <?php if ($chat['Webymsg']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $chat['Webymsg']['capture_date']; ?></td>
	<td><script type="text/javascript"> var txt="<?php echo $chat['Webymsg']['user']; ?>"; document.write(txt); </script></td>
	<td><a href="#" onclick="popupVetrina('/webymsgs/view/<?php echo $chat['Webymsg']['id']; ?>','scrollbar=auto'); return false"><?php echo $friend; ?></a></td>
	<td><?php echo $h.":".$m.":".$s; ?></td>
	<td><?php echo $chat['Webymsg']['data_size']; ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/webymsgs/info/<?php echo $chat['Webymsg']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a> <div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/' . $chat['Webymsg']['id']); ?></div></td>
  </tr>
 <?php else : ?>
  <tr>
        <td><b><?php echo $chat['Webymsg']['capture_date']; ?></b></td>
        <td><b><script type="text/javascript"> var txt="<?php echo $chat['Webymsg']['user']; ?>"; document.write(txt); </script></b></td>
        <td><b><a href="#" onclick="popupVetrina('/webymsgs/view/<?php echo $chat['Webymsg']['id']; ?>','scrollbar=auto'); return false"><?php echo $friend; ?></a></b></td>
        <td><b><?php echo $h.":".$m.":".$s; ?></b></td>
        <td><b><?php echo $chat['Webymsg']['data_size']; ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/webymsgs/info/<?php echo $chat['Webymsg']['id']; ?>','scrollbar=auto'); return false"><?php echo __('info.xml'); ?></a> <div class="ipcap"><?php echo $this->Html->link('pcap', 'pcap/' . $chat['Webymsg']['id']); ?></div></b></td>
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
