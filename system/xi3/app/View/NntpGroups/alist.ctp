<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic">
<div class="search">
<?php echo $this->Form->create('Search', array( 'url' => array('controller' => 'nntp_groups', 'action' => 'alist')));
      echo $this->Form->input('label', array('type'=>'text','size' => '40','maxlength'=>'40', 'label'=> __('Search:'), 'default' => $srchd));
      echo $this->Form->end(__('Go'));
 ?>
</div>
 <table id="messagelist" summary="Message list" cellspacing="0">
 <tr>
	<th class="date"><?php echo $this->Paginator->sort('capture_date', __('Date')); ?></th>
	<th class="subject"><?php echo $this->Paginator->sort('subject', __('Subject')); ?></th>
	<th class="from"><?php echo $this->Paginator->sort('sender', __('Sender')); ?></th>
	<th class="size"><?php echo $this->Paginator->sort('data_size', __('Size')); ?></th>
 </tr>
 <?php foreach ($nntp_articles as $article): ?>
 <?php if ($article['Nntp_article']['first_visualization_user_id']) : ?>
  <tr>
	<td><?php echo $article['Nntp_article']['capture_date']; ?></td>
        <?php if ($article['Nntp_article']['subject'] == "") : ?>
        <td><?php echo $this->Html->link("--",'/nntp_groups/view/' . $article['Nntp_article']['id']); ?></td>
        <?php else : ?>
	<td><?php echo $this->Html->link($article['Nntp_article']['subject'],'/nntp_groups/view/' . $article['Nntp_article']['id']); ?></td>
        <?php endif; ?>
	<td><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $article['Nntp_article']['sender'])); ?></td>
	<td><?php echo $article['Nntp_article']['data_size']; ?></td>
  </tr>
 <?php else : ?>
  <tr>
	<td><b><?php echo $article['Nntp_article']['capture_date']; ?></b></td>
        <?php if ($article['Nntp_article']['subject'] == "") : ?>
        <td><b><?php echo $this->Html->link("--",'/nntp_groups/view/' . $article['Nntp_article']['id']); ?></b></td>
        <?php else : ?>
	<td><b><?php echo $this->Html->link($article['Nntp_article']['subject'],'/nntp_groups/view/' . $article['Nntp_article']['id']); ?></td>
        <?php endif; ?>
	<td><b><?php echo str_replace('>', '&gt;', str_replace('<', '&lt;', $article['Nntp_article']['sender'])); ?></b></td>
	<td><b><?php echo $article['Nntp_article']['data_size']; ?></b></td>
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
