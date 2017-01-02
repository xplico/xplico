<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<h1><?php echo __('Cookie hijacking domain:'); ?> <?php echo $domain; ?> </h1>

<script type="text/javascript">
  <?php foreach ($cookies as $cookie) : ?>
      SetCookie('<?php echo $cookie; ?>', '/', '<?php echo $domain; ?>');
  <?php endforeach; ?>
</script>
<?php echo __('Now you can disable proxy and go to the url:'); ?> <a href="<?php echo 'http://'.htmlentities($url) ?>"><?php echo 'http://'.htmlentities($url) ?><a>