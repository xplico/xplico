<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">



<center>
<?php echo $form->create('Search',array( 'url' => array('controller' => 'ftps', 'action' => 'index')));
      echo $form->input('label', array('type'=>'text','size' => '40', 'label' => __('Search:', true), 'default' => $srchd));
     echo $form->end(__('Go', true));?>
</center>
</div>

<table id="messagelist" summary="Message list" cellspacing="0">
<tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="from"><?php echo $paginator->sort(__('Url', true), 'url'); ?></th>
        <th class="username"><?php echo $paginator->sort(__('User', true), 'username'); ?></th>
	<th class="number"><?php echo $paginator->sort(__('Download', true), 'download_num'); ?></th>
	<th class="number"><?php echo $paginator->sort(__('Upload', true), 'upload_num'); ?></th>
</tr>
<?php foreach ($ftps as $ftp): ?>
<?php if ($ftp['Ftp']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $ftp['Ftp']['capture_date']; ?></td>
	<td><?php echo $html->link($ftp['Ftp']['url'],'/ftps/view/' . $ftp['Ftp']['id']); ?></td>
        <td><?php echo $ftp['Ftp']['username']; ?></td>
	<td><?php echo $ftp['Ftp']['download_num']; ?></td>
	<td><?php echo $ftp['Ftp']['upload_num']; ?></td>
  </tr>
<?php else : ?>
 <tr>
	<td><b><?php echo $ftp['Ftp']['capture_date']; ?></b></td>
	<td><b><?php echo $html->link($ftp['Ftp']['url'],'/ftps/view/' . $ftp['Ftp']['id']); ?></b></td>
        <td><b><?php echo $ftp['Ftp']['username']; ?></b></td>
	<td><b><?php echo $ftp['Ftp']['download_num']; ?></b></td>
	<td><b><?php echo $ftp['Ftp']['upload_num']; ?></b></td>
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
