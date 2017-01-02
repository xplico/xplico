
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
<?php echo $this->Form->create('Search',array( 'url' => array('controller' => 'webs', 'action' => 'images')));
      echo $this->Form->input('label', array('type'=>'text','size' => '40', 'label'=>__('Search:'), 'default' => $srchd));
 echo $this->Form->end(__('Go'));?>
</div>
</center>

<table cellspacing="0">

<?php for ($grp=0; $grp!=3; $grp++): ?>
 <tr>
   <td class="webimgs">
   <?php if (!empty($images[($grp*4)])) : ?>
   <img class="webimgs" src="/webs/resBody/<?php echo $images[($grp*4)]['Web']['id']; ?>" />
   <?php endif ?>
   </td>
   <td class="webimgs">
   <?php if (!empty($images[($grp*4)+1])) : ?>
   <img class="webimgs" src="/webs/resBody/<?php echo $images[($grp*4)+1]['Web']['id']; ?>" />
   <?php endif ?>
   </td>
   <td class="webimgs">
   <?php if (!empty($images[($grp*4)+2])) : ?>
   <img class="webimgs" src="/webs/resBody/<?php echo $images[($grp*4)+2]['Web']['id']; ?>" "/>
   <?php endif ?>
   </td>
   <td class="webimgs">
   <?php if (!empty($images[($grp*4)+3])) : ?>
   <img class="webimgs" src="/webs/resBody/<?php echo $images[($grp*4)+3]['Web']['id']; ?>" />
   <?php endif ?>
   </td>
 </tr>
 <tr>
   <td class="webimgs">
   <?php if (!empty($images[($grp*4)])) : ?>
   <?php echo $images[($grp*4)]['Web']['host']; ?><br/>
   <a href="#" onclick="popupVetrina('/webs/view/<?php echo $images[($grp*4)]['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo __('Image'); ?></a>  <?php echo __('or'); ?> <a href="#" onclick="popupVetrina('/webs/imgpage/<?php echo $images[($grp*4)]['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo __('Page'); ?></a>
   <?php endif ?>
   </td>
   <td class="webimgs">
   <?php if (!empty($images[($grp*4)+1])) : ?>
   <?php echo $images[($grp*4)+1]['Web']['host']; ?><br/>
   <a href="#" onclick="popupVetrina('/webs/view/<?php echo $images[($grp*4)+1]['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo __('Image'); ?></a> <?php echo __(' or'); ?> <a href="#" onclick="popupVetrina('/webs/imgpage/<?php echo $images[($grp*4)+1]['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo __('Page'); ?></a>
   <?php endif ?>
   </td>
   <td class="webimgs">
   <?php if (!empty($images[($grp*4)+2])) : ?>
   <?php echo $images[($grp*4)+2]['Web']['host']; ?><br/>
   <a href="#" onclick="popupVetrina('/webs/view/<?php echo $images[($grp*4)+2]['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo __('Image'); ?></a>  <?php echo __('or'); ?> <a href="#" onclick="popupVetrina('/webs/imgpage/<?php echo $images[($grp*4)+2]['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo __('Page'); ?></a>
   <?php endif ?>
   </td>
   <td class="webimgs">
   <?php if (!empty($images[($grp*4)+3])) : ?>
   <?php echo $images[($grp*4)+3]['Web']['host']; ?><br/>
   <a href="#" onclick="popupVetrina('/webs/view/<?php echo $images[($grp*4)+3]['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo __('Image'); ?></a> <?php echo __(' or'); ?> <a href="#" onclick="popupVetrina('/webs/imgpage/<?php echo $images[($grp*4)+3]['Web']['id']; ?>','scrollbar=auto'); return false"><?php echo __('Page'); ?></a>
   <?php endif ?>
   </td>
 </tr>
<?php endfor; ?>
</table>
<table id="listpage" summary="Message list" cellspacing="0">
<tr>
	<th class="next"><?php echo $this->Paginator->prev(__('Previous'), array(), null, array('class'=>'disabled')); ?></th>
       	<th><?php echo $this->Paginator->numbers(); echo '<br/>'.$this->Paginator->counter(); ?></th>
	<th class="next"><?php echo $this->Paginator->next(__('Next'), array(), null, array('class' => 'disabled')); ?></th>
</tr>
</table>
</div>
