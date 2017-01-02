<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" dir="ltr" lang="en">


<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title><?php echo __('Chat'); ?></title>
  <?php echo $this->Html->css('facebookchat');?>
  
  <script type="text/javascript">
    var refreshId = setInterval(function() {
      location.reload();
    }, 5000);
  </script>
</head>

	
<body>
<?php
    echo $content_for_layout;
?>
</body>
</html>
