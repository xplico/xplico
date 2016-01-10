<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">
<?php echo $form->create('Search', array( 'url' => array('controller' => 'nntp_groups', 'action' => 'alist')));
      echo $form->input('label', array('type'=>'text','size' => '40','maxlength'=>'40', 'label'=> __('Search:', true), 'default' => $srchd));
      echo $form->end(__('Go', true));
 ?>
</div>
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $paginator->sort(__('Date', true), 'capture_date'); ?></th>
	<th class="subject"><?php echo $paginator->sort(__('Subject', true), 'subject'); ?></th>
	<th class="from"><?php echo $paginator->sort(__('Sender', true), 'sender'); ?></th>
	<th class="size"><?php echo $paginator->sort(__('Size', true), 'data_size'); ?></th>
 </tr>
 <?php foreach ($nntp_articles as $article): ?>
 <?php if ($article['Nntp_article']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $article['Nntp_article']['capture_date']; ?></td>
        <?php if ($article['Nntp_article']['subject'] == "") : ?>
        <td><?php echo $html->link("--",'/nntp_groups/view/' . $article['Nntp_article']['id']); ?></td>
        <?php else : ?>
	<td><?php echo $html->link($article['Nntp_article']['subject'],'/nntp_groups/view/' . $article['Nntp_article']['id']); ?></td>
        <?php endif; ?>
	<td><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $article['Nntp_article']['sender'])); ?></td>
	<td><?php echo $article['Nntp_article']['data_size']; ?></td>
  </tr>
 <?php else : ?>
  <tr>
	<td><b><?php echo $article['Nntp_article']['capture_date']; ?></b></td>
        <?php if ($article['Nntp_article']['subject'] == "") : ?>
        <td><b><?php echo $html->link("--",'/nntp_groups/view/' . $article['Nntp_article']['id']); ?></b></td>
        <?php else : ?>
	<td><b><?php echo $html->link($article['Nntp_article']['subject'],'/nntp_groups/view/' . $article['Nntp_article']['id']); ?></td>
        <?php endif; ?>
	<td><b><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $article['Nntp_article']['sender'])); ?></b></td>
	<td><b><?php echo $article['Nntp_article']['data_size']; ?></b></td>
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
