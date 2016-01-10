<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<script type='text/javascript'>
$(function() {
    $("#hoff").button();
    $("#hon").button();
    if (<?php echo $help; ?>) {
      $("#help_off").hide();
    }
    else {
      $("#help_on").hide();
    }
    $("#hoff, #hon").click(function() {
      $("#help_off").toggle(1000);
      $("#help_on").toggle(500);
    });
});
</script>

<div id="help_off">
<?php echo $this->Session->flash(); ?>
 <?php if ($pbar) : ?>
	<script>
	$(function() {
		$( "#progressbar" ).progressbar({
			value: <?php echo $est_time_perc; ?>

		});
	});
	</script>
 <?php endif ?>


  <div class="solinfo">
    <div class="sol">
       <h2><?php __('Session Data'); ?></h2>
     <?php if ($pbar) : ?>
       <div id="progressbar"></div>
       <div id="progressbar_et"><?php __('E.T.'); ?>: <?php echo $est_time; ?> sec</div>
       <div class="cline"> </div>
     <?php endif ?>
       <dl>
	<dt><?php __('Case and Session name'); ?></dt>
	<dd><?php echo $html->link($sol['Pol']['name'], '/pols/view/' .$sol['Pol']['id']).' -> '.$sol['Sol']['name']; ?></dd>
	<dt><?php __('Cap. Start Time'); ?></dt>
	<dd><?php if ($sol['Sol']['start_time'] != '1990-01-01 00:00:00') echo $sol['Sol']['start_time']; else echo '---'; ?></dd>
	<dt><?php __('Cap. End Time'); ?></dt>
	<dd><?php if ($sol['Sol']['start_time'] != '1990-01-01 00:00:00') echo $sol['Sol']['end_time']; else echo '---'; ?></dd>
	<dt><?php __('Status'); ?></dt>
	<dd><?php echo $sol['Sol']['status']; ?></dd>
        <dt><?php __('Hosts'); ?></dt>
        <?php if (empty($hosts)): ?>
        <dd>---</dd>
        <?php else : ?>
        <dd id='hosts'> 

	<?php
	 echo $form->create('host', array('url' => array('controller' => 'sols', 'action' => 'host')));
	$hosts[0] = __('View all hosts', true);
         echo $form->select('host', $hosts, $hosts[0]);
	 echo $form->end(__('Filter', true));
	?>
        </dd>
        <?php endif; ?>
       </dl>
     </div>
  </div>
  <div class="pcap_input">
    <div class="sol" id='pcap_upload'>

    <?php if (!$live) : ?>
     <h2><?php __('Pcap set'); ?></h2>
     <?php if ($last_sol == 1): ?>
       <?php if (!$register && isset($pcapip_port)): ?>
       <h4>PCAP-over-IP TCP port: <a href="http://wiki.xplico.org/doku.php?id=pcap-over-ip"><?php echo $pcapip_port; ?></a>.</h4>
       <?php endif; ?>
     <h4><?php __('Add new pcap file'); ?>.</h4>

     <?php
     echo $form->create(__('Sols', true), array('action' => 'pcap', 'type' => 'file'));
     echo $form->file('File', array('label' => __('File', true)));
     echo $form->end(__('Upload', true));
     ?>
     <?php else: ?>
     <strong><?php __('Not possible to add new pcap files.'); ?><br/><br/><br/></strong>
     <div class="cline"> </div>
     <?php endif; ?>
     <?php if ($register): ?>
       <button id="hon" type="button" style="float: right;"><?php __('Rules'); ?></button>
     <?php endif; ?>
     <h4><?php echo $html->link(__('List', true), '/inputs/index'); ?> <?php __('of all pcap files'); ?>.</h4>
     <div class="cline"> </div>
     <?php else : ?>
     <h2><?php __('Live'); ?></h2>
      <?php if ($livestop) : ?>
	<center>
	<!-- To-do: display, just for info puropouses, the interface name that is currently sniffing.-->
	<br />
<font color="red">	<?php __('Listening at interface'); ?>: <b><?php echo $interff; ?></b></font> <!-- to-do: move this into a CSS -->
	<br />	<br />
        <?php echo $form->create('/sol', array ('action' => 'livestop')); ?>
        <?php echo $form->end('Stop'); ?>
	</center>

      <?php else : ?>
        <center>
        <?php echo $form->create('sol', array ('action' => 'live'));?>
	<br />
        <b><?php __('Interface'); ?>:</b>
	<?php  echo $form->select('Interface.Type', array($interface,null,null,'Choose adaptor')); ?>
	<br /><br />
        <?php echo $form->end(__('Start', true)); ?>
	</center>


      <?php endif ?>
     <?php endif ?>
     
    </div>
  </div>
  <div class="cline"> </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('HTTP'); ?></h3>
      <dl>
        <dt><?php __('Post'); ?></dt>
        <dd><?php echo $web_post; ?></dd>
        <dt><?php __('Get'); ?></dt>
        <dd><?php echo $web_get; ?></dd>
        <dt><?php __('Video'); ?></dt>
        <dd><?php echo $web_video; ?></dd>
        <dt><?php __('Images'); ?></dt>
        <dd><?php echo $web_image; ?></dd>
     </dl>
    </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('MMS'); ?></h3>
      <dl>
        <dt><?php __('Number'); ?></dt>
        <dd><?php echo $mms_num; ?></dd>
        <dt><?php __('Contents'); ?></dt>
        <dd><?php echo $mms_cont; ?></dd>
        <dt><?php __('Video'); ?></dt>
        <dd><?php echo $mms_video; ?></dd>
        <dt><?php __('Images'); ?></dt>
        <dd><?php echo $mms_image; ?></dd>
     </dl>
    </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('Emails'); ?></h3>
      <dl>
        <dt><?php __('Received'); ?></dt>
        <dd><?php echo $eml_received ?></dd>
        <dt><?php __('Sent'); ?></dt>
        <dd><?php echo $eml_sended ?></dd>
        <dt><?php __('Unreaded'); ?></dt>
        <dd><?php echo $eml_unread.'/'.$eml_total ?></dd>
     </dl>
   </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('FTP - TFTP - HTTP file'); ?></h3>
      <dl>
        <dt><?php __('Connections'); ?></dt>
        <dd><?php echo $ftp_num." - ".$tftp_num; ?></dd>
        <dt><?php __('Downloaded'); ?></dt>
        <dd><?php echo $ftp_down." - ".$tftp_down; ?></dd>
        <dt><?php __('Uploaded'); ?></dt>
        <dd><?php echo $ftp_up." - ".$tftp_up; ?></dd>
        <dt><?php __('HTTP'); ?></dt>
        <dd><?php echo $httpfile_num; ?></dd>
     </dl>
   </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('Web Mail'); ?></h3>
      <dl>
        <dt><?php __('Total'); ?></dt>
        <dd><?php echo $webmail_num; ?></dd>
        <dt><?php __('Received'); ?></dt>
        <dd><?php echo $webmail_receiv; ?></dd>
        <dt><?php __('Sent'); ?></dt>
        <dd><?php echo $webmail_sent; ?></dd>
     </dl>
    </div>
  </div>
  <div class="cline"> </div>

  <div class="solbox">
    <div class="sol">
      <h3><?php __('Facebook Chat / Paltalk'); ?></h3>
      <dl>
        <dt><?php __('Users'); ?></dt>
        <dd><?php echo $fbc_users; ?></dd>
        <dt><?php __('Chats'); ?></dt>
        <dd><?php echo $fbc_chats.'/'.$paltalk_num; ?></dd>
     </dl>
    </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('IRC/Paltalk Exp/Msn/Yahoo!'); ?></h3>
      <dl>
        <dt><?php __('Server'); ?></dt>
        <dd><?php echo $irc_num; ?></dd>
        <dt><?php __('Channels'); ?></dt>
        <dd><?php echo $irc_chnl_num.'/'.$paltalk_exp_num.'/'.$msn_num.'/'.$webymsg; ?></dd>
     </dl>
      
   </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('Dns - Arp - Icmpv6'); ?></h3>
      <dl>
        <dt><?php __('DNS res'); ?></dt>
        <dd><?php echo $dns_num; ?></dd>
        <dt><?php __('ARP/ICMPv6'); ?></dt>
        <dd><?php echo $arp_num.'/'.$icmpv6_num; ?></dd>
      </dl>
    </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('RTP/VoIP'); ?></h3>
       <dl>
        <dt><?php __('Video'); ?></dt>
        <dd><?php echo $rtp_video ?></dd>
        <dt><?php __('Audio'); ?></dt>
        <dd><?php echo $rtp_audio ?></dd>
       </dl>
    </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('NNTP'); ?></h3>
      <dl>
        <dt><?php __('Groups'); ?></dt>
        <dd><?php echo $nntp_grp; ?></dd>
        <dt><?php __('Articles'); ?></dt>
        <dd><?php echo $nntp_artcl; ?></dd>
     </dl>
    </div>
  </div>
  <div class="cline"> </div>


  <div class="solbox">
    <div class="sol">
      <h3><?php echo _('Feed').' & '._('Printed files'); ?></h3>
      <dl>
        <dt><?php __('Number'); ?></dt>
        <dd><?php echo $feed_num; ?></dd>
        <dt><?php __('Pdf'); ?></dt>
        <dd><?php echo $pjl_num; ?></dd>
      </dl>
   </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('WhatsApp'); ?></h3>
      <dl>
        <dt><?php __('Connection'); ?></dt>
        <dd><?php echo $whatsapp_num; ?></dd>
      </dl>
    </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('Telnet / Syslog'); ?></h3>
      <dl>
        <dt><?php __('Connections'); ?></dt>
        <dd><?php echo $telnet_num.'/'.$syslog_num; ?></dd>
      </dl>
    </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('SIP'); ?></h3>
       <dl>
        <dt><?php __('Calls'); ?></dt>
        <dd><?php echo $sip_calls ?></dd>
       </dl>
    </div>
  </div>
  <div class="solbox">
    <div class="sol">
      <h3><?php __('Undecoded'); ?></h3>
      <dl>
        <dt><?php __('Text flows'); ?></dt>
        <dd><?php echo $text_num; ?></dd>
        <dt><?php __('Dig'); ?></dt>
        <dd><?php echo $dig_num; ?></dd>
     </dl>
    </div>
  </div>
</div>
<div id="help_on">
  <div class="sol">
    <h3><?php __('Rules'); ?></h3>
    <ul>
      <li><strong><?php __('All data will be deleted at'); ?>: 00:00 GMT</strong></li>
      <li><?php __('Max pcap file size'); ?>: <strong>5MB</strong>.<?php __(' Larger files will be rejected. There is no limit on how many packets the capture file contains.'); ?></li>
      <li><strong><?php __('Total pcap size limit'); ?>: 10MB</strong></li>
      <li><?php __("While the decoded data are not shared, we make no claims that your data is not viewable by other users. For now, if you want to protect sensitive data in your capture files, don't use the free XplicoDemo service."); ?></li>
      <li><?php __("We recommend using Firefox 3.x, Safari 4.x or greater, or Google Chrome."); ?>
    </ul> 
    <button id="hoff" type="button"><?php __('Ok'); ?></button>
  </div>
</div>

  <div class="cline"> </div>
