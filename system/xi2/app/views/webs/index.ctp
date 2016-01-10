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

<script language="JavaScript">
$(function() {
	// setup overlay actions to buttons
	$("button[rel]").overlay({
		// use the Apple effect for overlay
		effect: 'apple',		
		
		expose: '#789',				
		
		onLoad: function(content) {
			// find the player contained inside this overlay and load it
			this.getOverlay().find("a.player").flowplayer(0).load();
		},
		
		onClose: function(content) {
			$f().unload();
		}

	});				
	
	// install flowplayers
	$("a.player").flowplayer("/files/flowplayer-3.2.2.swf");
});	
</script>

<div class="generic">
 <div class="search">

<!-- CODE FOR SELECTING WEB TYPE CONTENTS-->
<center>
<?php echo $form->create('webcontent', array('url' => array('controller' => 'webs', 'action' => 'index')));
      echo '<label>'.__('Web URLs:', true).'</label>';
      echo $form->radio('type', array(__('Html', true), __('Image', true), __('Flash', true), __('Video', true), __('Audio', true), __('JSON', true), __('All', true)) , array('separator' => ' ',  'legend' => false, 'default' => $checked ));
      echo $form->input('search', array('type'=>'text','size' => '40', 'label' => __('Search:', true), 'default' => $srchd));
echo $form->end(__('Go', true));?>
</center>
</div>
<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th><?php echo $paginator->sort(__('Url', true), 'url'); ?></th>
        <th class="plfl"><p></p></th>
        <th class="size"><?php echo $paginator->sort(__('Size', true), 'rs_bd_size'); ?></th>
        <th class="methos"><?php echo $paginator->sort(__('Method', true), 'method'); ?></th>
	<th class="info"><?php __('Info'); ?></th>
</tr>
<?php foreach ($webs as $web): ?>
<?php if ($web['Web']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $web['Web']['capture_date']; ?></td>
        <?php if (stripos($web['Web']['content_type'], 'video') === false && stripos($web['Web']['url'], '.flv') === false) : ?>
          <td class="url"><a href="#" onclick="popupVetrina('/webs/view/<?php echo $web['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo htmlentities($web['Web']['url']); ?></a></td>
          <td><p> </p></td>
        <?php else : ?>
          <td class="url"><?php echo $html->link(htmlentities($web['Web']['url']),'/webs/play/' . $web['Web']['id']); ?></td>
          <td><button rel="<?php echo '#overlay'. $web['Web']['id']; ?>"></button></td>
            <div class="overlay" id="<?php echo 'overlay'. $web['Web']['id']; ?>">
		<a class="player" href="<?php echo '/webs/resBody/' . $web['Web']['id'] . '?.flv'; ?>">
			&nbsp;
		</a>
            </div>
        <?php endif ?>
        <td><?php echo $web['Web']['rs_bd_size']; ?></td>
        <td><?php echo $html->link($web['Web']['method'],'/webs/method/' . $web['Web']['id']); ?></td>
        <td class="pinfo"><a href="#" onclick="popupVetrina('/webs/info/<?php echo $web['Web']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a> <div class="iweb"><div class="ipcap"><?php echo $html->link('pcap', 'pcap/' . $web['Web']['id']); ?></div>
         <div><a title="Enable the Proxy before click!" href="#" onclick="popupVetrina('http://<?php echo $web['Web']['host']; ?>/webs/hijacking/<?php echo $web['Web']['id']; ?>','scrollbar=auto'); return false">cookies</a></div></div>
        </td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $web['Web']['capture_date']; ?></b></td>
        <?php if (stripos($web['Web']['content_type'], 'video') === false && stripos($web['Web']['url'], '.flv') === false) : ?>
          <td class="url"><b><a href="#" onclick="popupVetrina('/webs/view/<?php echo $web['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo htmlentities($web['Web']['url']); ?></a></b></td>
          <td><p> </p></td>
        <?php else : ?>
          <td class="url"><b><?php echo $html->link(htmlentities($web['Web']['url']),'/webs/play/' . $web['Web']['id']); ?></b></td>
          <td><button rel="<?php echo '#overlay'. $web['Web']['id']; ?>"></button> </td>
            <div class="overlay" id="<?php echo 'overlay'. $web['Web']['id']; ?>">
		<a class="player" href="<?php echo '/webs/resBody/' . $web['Web']['id'] . '?.flv'; ?>">
			&nbsp;
		</a>
            </div>
        <?php endif ?>
        <td><b><?php echo $web['Web']['rs_bd_size']; ?></b></td>
        <td><b><?php echo $html->link($web['Web']['method'],'/webs/method/' . $web['Web']['id']); ?></b></td>
        <td class="pinfo"><b><a href="#" onclick="popupVetrina('/webs/info/<?php echo $web['Web']['id']; ?>','scrollbar=auto'); return false"><?php __('info.xml'); ?></a></b> <div class="iweb"><div class="ipcap"><b><?php echo $html->link('pcap', 'pcap/' . $web['Web']['id']); ?></b></div>
         <div><b><a title="Enable the Proxy before click!" href="#" onclick="popupVetrina('http://<?php echo $web['Web']['host']; ?>/webs/hijacking/<?php echo $web['Web']['id']; ?>','scrollbar=auto'); return false">cookies</a></b></div></div>
        </td>
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
