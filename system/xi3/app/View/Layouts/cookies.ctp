<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" dir="ltr" lang="en">


<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title><?php echo __('Cookie hijacking'); ?></title>
  <?php echo $this->Html->css('facebookchat');?>
  <script type="text/javascript">
  function SetCookie( namevalue, path, domain)
  {
     var expires_date = "Tue, 2 Feb 2020 02:02:02 GMT";
     
     var t = namevalue + ";expires=" + expires_date +
         ( ( path ) ? ";path=" + path : "" ) +
         ( ( domain ) ? ";domain=" + domain : "" );
     document.cookie = t;
  }
  </script>
</head>

	
<body>
<?php
    echo $content_for_layout;
?>
</body>
</html>
