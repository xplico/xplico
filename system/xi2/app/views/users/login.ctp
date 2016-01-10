<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<script type='text/javascript'>
function Lang()
{
    if ($(this).val() != "--Language--") {
         window.location.href='/users/login/'+$(this).val();
    }
}

$(function() {
    $("#lang").change(Lang);
    $(".sol").css('minWidth', 250);
    $(".sol").width(250);
    $("h3").css("background-color", "#FF3300");
    $("h3").css("font-size", 14);
    $("#center").css('height',400);
});
</script>

<?php if ( $isXplicoRunning == 1) : ?>
  <div id="login" align="center">
  <select id="lang">
    <option>--Language--</option>
    <option value="ara">Arabic</option>
    <option value="zh_cn">Chinese</option>
    <option value="zh_tw">Chinese (Taiwan)</option>
    <option value="deu">German</option>
    <option value="eng">English</option>
    <option value="fre">French</option>
    <option value="hin">Hindi</option>
    <option value="ita">Italian</option>
    <option value="jpn">Japanese</option>
    <option value="por">Portuguese</option>
    <option value="pt_br">Portuguese (Brazil)</option>
    <option value="rus">Russian</option>
    <option value="spa">Spanish</option>
    <option value="tur">Turkish</option>
  </select>
  <h1><?php __('Please login'); ?></h1>
  <br />
  <?php echo $form->create('User', array('action' => 'login')); ?>
  <?php echo $form->input('username', array('maxlength'=> 15, 'size' => 15, 'label' => __('Username', true))); ?>
  <?php echo $form->input('password', array('size' => 15, 'label' => __('Password', true))); ?><br />
  <?php echo $form->submit(__('Login', true)); ?>
  <?php echo $form->end(); ?>
  </div>
  <?php if ($register) : ?>
    <div id="login" align="center">
      <b><a href="/users/register"><?php __('Create an account'); ?></a></b>
    </div>
  <?php endif; ?>
<?php endif; ?>


