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
  <h1><?php echo __('Please login'); ?></h1>
  <br />
  <?php echo $this->Form->create('User', array('url' => 'login')); ?>
  <?php echo $this->Form->input('username', array('maxlength'=> 15, 'size' => 15, 'label' => __('Username'))); ?>
  <?php echo $this->Form->input('password', array('size' => 15, 'label' => __('Password'))); ?><br />
  <?php echo $this->Form->submit(__('Login')); ?>
  <?php echo $this->Form->end(); ?>
  </div>
  <div class="sol" style="position: absolute; top: 60pt; left: 120pt; z-index: 100;">
    <h3><?php echo __('Last Change'); echo ' 02-01-2017'; ?></h3>
    <a href="https://twitter.com/xplico" class="twitter-follow-button" data-show-count="false">Follow @xplico</a>
    <script src="//platform.twitter.com/widgets.js" type="text/javascript"></script>
  </div>
  <?php if ($register) : ?>
    <div id="login" align="center">
      <b><a href="/users/register"><?php echo __('Create an account'); ?></a></b>
    </div>
  <?php endif; ?>
<?php endif; ?>


