<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>
<html xmlns="http://www.w3.org/1999/xhtml">

<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2012, http://www.xplico.org
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
  <?php echo $html->css('style');?>
  <?php echo $html->css('html');?>
  <?php echo $html->css('mail');?>
  <?php echo $html->css('webimages');?>
  <?php echo $html->css('themes/ui-darkness/jquery-ui-custom.css'); ?>
  <?php
        echo $html->script('jquery.js');
        echo $html->script('jquery-ui-custom.min.js');
        echo $html->script('http_get.js');
        echo $html->script('jquery.tools.min.js');
        echo $html->script('flowplayer-3.2.2.min.js');
        echo $html->script('swfobject.js');
  ?>

  <?php if (!isset($menu_left)) {
            $menu_left = array('active' => '0', 'sections' => array(array('name' => __('Info', true), 'sub' => array(array('name' => __('About', true), 'link' => '/users/about'), array('name' => __('Wiki', true), 'link' => 'http://wiki.xplico.org'), array('name' => __('Forum', true), 'link' => 'http://forum.xplico.org'), array('name' => __('Licenses', true), 'link' => '/users/licenses')))));
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
<img id="devel_image" style="position: fixed; top: 0pt; right: 0pt; border: 0pt none; z-index: 100;" src="<?php echo $html->url("/img/devel.png") ?>" alt="">
<!-- #content: holds all except site footer - causes footer to stick to bottom -->
<div id="page">
  <!-- #header: holds the logo and top links -->
  <div id="header">
    <h1><?php echo $html->link('Xplico', '/') ?> <?php __('Interface'); ?></h1>
    <?php if ($session->read('user')): ?>
      <h2><?php __('User:'); ?> <span><?php echo $session->read('user') ?> </span></h2>
    <?php endif; ?>
  </div>
  <!-- #header end -->

  <!-- #menu: the main large box site menu -->
  <div id="main_menu">
    <div id="mmenu_list">
      <ul>
      <?php if ($session->read('user')): ?>
        <?php if (isset($menu_bare)):  ?>
           <?php foreach ($menu_bare as $mb_elem): ?>
             <li><?php echo $html->link($mb_elem['label'], $mb_elem['link']); ?></li>
           <?php endforeach; ?>
        <?php endif; ?>
        <?php if ($session->check('admin')):  ?>
           <li><?php echo $html->link(__('Admin', true), '/admins') ?></li>
        <?php endif; ?>
        <li><?php echo $html->link(__('Help', true), '/users/help') ?></li>
        <li><?php echo $html->link(__('Forum', true), 'http://forum.xplico.org') ?></li>
        <li><?php echo $html->link(__('Wiki', true), 'http://wiki.xplico.org') ?></li>
        <li><?php echo $html->link(__('CapAnalysis', true), 'http://www.capanalysis.net') ?></li>
        <li><?php echo $html->link(__('Change password', true), '/users/cpassword') ?></li>
        <li><?php echo $html->link(__('Licenses', true), '/users/licenses') ?></li>
        <li><?php echo $html->link(__('Logout', true), '/users/logout') ?></li>
      <?php else: ?>
        <li><?php echo $html->link(__('Login', true), '/users/login') ?></li>
        <li><?php echo $html->link(__('Licenses', true), '/users/licenses') ?></li>
        <!-- <li><?php echo $html->link(__('Register', true), '/users/register') ?></li> -->
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
                      <li><?php echo $html->link($submenu['name'], $submenu['link']) ?></li>
            	    <?php endforeach; ?>
                    </ul>
            	</div>
        <?php endforeach; ?>
      </div>
      <div id="adv">
         <a href="http://www.capanalysis.net">
            <img alt="Web pcap file Viewer" title="PCAP from another point of view" src="<?php echo $html->url("/img/capanalysis.png") ?>"></img>
        </a>
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
    &copy; 2007-2015 Gianluca Costa & Andrea de Franceschi. All Rights Reserved.<br/>
    </p>
    <p id="link_icon">
    <a href="http://www.xplico.org">
                <img alt="Xplico" title="Xplico" src="<?php echo $html->url("/img/button-xplico.png") ?>"></img>
    </a>
    <a href="http://www.cakephp.org">
                <img alt="Cakephp power" title="Cakephp power" src="<?php echo $html->url("/img/cake.power.png") ?>"></img>
    </a>
    </span>
    </p>
  </div>
  <!-- #footer end -->
</div>

</body>
</html>
