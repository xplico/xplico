<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>
<html xmlns="http://www.w3.org/1999/xhtml">

<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2017, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<head>

  <!-- Meta Data -->
  <?php echo $this->Html->charset(); ?>
  <meta name="author" content="Gianluca Costa & Andrea de Franceschi" />
  <meta name="description" content="The internet traffic decoder interface" />
  <meta name="keywords" content="decoder, internet, ip, traffic, interception, pcap" />

  <?php if (isset($refresh_time)):  ?>
      <meta http-equiv="refresh" content="<?php echo $refresh_time ?>">
  <?php endif; ?>
  <!-- Site Title -->
  <title>Xplico ..:<?php echo $title_for_layout;?>:..</title>
  <!-- Link to Style External Sheet -->
  <?php echo $this->Html->css('style');?>
  <?php echo $this->Html->css('html');?>
  <?php echo $this->Html->css('mail');?>
  <?php echo $this->Html->css('webimages');?>
  <?php echo $this->Html->css('themes/ui-darkness/jquery-ui-custom.css'); ?>
  <?php
        echo $this->Html->script('jquery.js');
        echo $this->Html->script('jquery-ui-custom.min.js');
        echo $this->Html->script('http_get.js');
        echo $this->Html->script('jquery.tools.min.js');
        echo $this->Html->script('flowplayer-3.2.2.min.js');
        echo $this->Html->script('swfobject.js');
  ?>

  <?php if (!isset($menu_left)) {
            $menu_left = array('active' => '0', 'sections' => array(array('name' => __('Info'), 'sub' => array(array('name' => __('About'), 'link' => '/users/about'), array('name' => __('Wiki'), 'link' => 'http://wiki.xplico.org'), array('name' => __('Forum'), 'link' => 'http://forum.xplico.org'), array('name' => __('Licenses'), 'link' => '/users/licenses')))));
       }
  ?>
  <script type="text/javascript">
	$(function() {
		$("#accordion").accordion({
		    autoHeight: false,
		    collapsible: true,
		    active: <?php echo $menu_left['active']; ?>,
	            icons: {
    			header: "ui-icon-circle-arrow-e",
   				headerSelected: "ui-icon-circle-arrow-s"
			}
		});
        $("#devel_image").click(function () { 
            $(this).slideUp();
        });
	});
  </script>
</head>

<body>
<!--
<img id="devel_image" style="position: fixed; top: 0pt; right: 0pt; border: 0pt none; z-index: 100;" src="<?php echo $this->Html->url("/img/devel.png") ?>" alt="">
-->
<!-- #content: holds all except site footer - causes footer to stick to bottom -->
<div id="page">
  <!-- #header: holds the logo and top links -->
  <div id="header">
    <h1><?php echo $this->Html->link('Xplico', '/') ?> <?php echo __('Interface'); ?></h1>
    <?php if ($this->Session->read('user')): ?>
      <h2><?php echo __('User:'); ?> <span><?php echo $this->Session->read('user') ?> </span></h2>
    <?php endif; ?>
  </div>
  <!-- #header end -->

  <!-- #menu: the main large box site menu -->
  <div id="main_menu">
    <div id="mmenu_list">
      <ul>
      <?php if ($this->Session->read('user')): ?>
        <?php if (isset($menu_bare)):  ?>
           <?php foreach ($menu_bare as $mb_elem): ?>
             <li><?php echo $this->Html->link($mb_elem['label'], $mb_elem['link']); ?></li>
           <?php endforeach; ?>
        <?php endif; ?>
        <?php if ($this->Session->check('admin')):  ?>
           <li><?php echo $this->Html->link(__('Admin'), '/admins') ?></li>
        <?php endif; ?>
        <li><?php echo $this->Html->link(__('Help'), '/users/help') ?></li>
        <li><?php echo $this->Html->link(__('Forum'), 'http://forum.xplico.org') ?></li>
        <li><?php echo $this->Html->link(__('Wiki'), 'http://wiki.xplico.org') ?></li>
        <li><?php echo $this->Html->link(__('CapAnalysis'), 'http://www.capanalysis.net') ?></li>
        <li><?php echo $this->Html->link(__('Change password'), '/users/cpassword') ?></li>
        <li><?php echo $this->Html->link(__('Licenses'), '/users/licenses') ?></li>
        <li><?php echo $this->Html->link(__('Logout'), '/users/logout') ?></li>
      <?php else: ?>
        <li><?php echo $this->Html->link(__('Login'), '/users/login') ?></li>
        <li><?php echo $this->Html->link(__('Licenses'), '/users/licenses') ?></li>
        <!-- <li><?php echo $this->Html->link(__('Register'), '/users/register') ?></li> -->
      <?php endif; ?>
      </ul>
    </div>
  </div>
  <!-- #menu end -->

  <!-- #content_wrapper: holds the page content -->
  <div id="content_wrapper">
    <div id="adminmenu">
      <div id="accordion">
        <?php foreach ($menu_left['sections'] as $section): ?>
            	<h3><a href="#"><?php echo $section['name']; ?></a></h3>
            	<div>
            	    <ul>
            	    <?php foreach ($section['sub'] as $submenu): ?>
                      <li><?php echo $this->Html->link($submenu['name'], $submenu['link']) ?></li>
            	    <?php endforeach; ?>
                    </ul>
            	</div>
        <?php endforeach; ?>
      </div>
      <div id="adv">
         <a href="http://www.capanalysis.net">
            <img alt="Web pcap file Viewer" title="PCAP from another point of view" src="<?php echo $this->Html->url("/img/capanalysis.png") ?>"></img>
        </a>
      </div>
	  <div align="center">
		<a href="https://twitter.com/xplico" class="twitter-follow-button" data-show-count="false">Follow @xplico</a>
		<script src="https://platform.twitter.com/widgets.js" type="text/javascript"></script>
	  </div>
    </div>

    <div id="center">
      <?php
         echo $this->Session->flash();
         echo $content_for_layout;
      ?>
    </div>
    <div class="cline"> </div>
  </div>
  <!-- #page end -->
  <!-- #footer: holds the site footer (logo and links) -->
  <div id="footer">
    <p id="autor">
    &copy; 2007-2017 Gianluca Costa & Andrea de Franceschi. All Rights Reserved.<br/>
    </p>
    <p id="link_icon">
    <a href="http://www.xplico.org">
                <img alt="Xplico" title="Xplico" src="<?php echo $this->Html->url("/img/button-xplico.png") ?>"></img>
    </a>
    <a href="http://www.cakephp.org">
                <img alt="Cakephp power" title="Cakephp power" src="<?php echo $this->Html->url("/img/cake.power.png") ?>"></img>
    </a>
    </span>
    </p>
  </div>
  <!-- #footer end -->
</div>

</body>
</html>
