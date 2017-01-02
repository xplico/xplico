<!--
Copyright:  Carlos Gacimartín <cgacimartin@gmail.com>
    Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<center>
<div class="configurations form" >
<fieldset>
	<legend><b><?php echo __('Xplico Control pane'); ?></b></legend>
 <div class="cline"> </div>

  <div class="confbox">
    <div class="conf">
      <h3><?php echo __('Checksum validation'); ?></h3>
	<p><?php echo __('Option to enable/disable checksum analysis. Without checksum verification more information will be decoded, but it is not legally reliable, as those packets may have been sent by any other host.'); ?>
	</p>
	<br />
         <?php if ($isChecksumValidationActivated == 0) {
                        echo $this->Html->image('enable.gif');
                        echo "<br />";
                        echo __('Validating checksums:').' <b>'. __('OFF').'</b>';
                        $changeChecksumValidationStatusTo = "1";       }
                else {
                        echo $this->Html->image('disable.gif');
                        echo "<br />";
                        echo __('Validating checksum:').' <b>'.__('ON').'</b>';
                        $changeChecksumValidationStatusTo = "0";        }
                ?>
	  <br />

	    <?php echo $this->Form->create(null, array('url' => array('controller' => 'configurations', 'action' => 'checksumtogle')));?>
            <?php echo $this->Form->hidden('checksumStatus', array('value'=>$changeChecksumValidationStatusTo));?>
            <?php if ($isChecksumValidationActivated == 0) {
                        echo $this->Form->end(__('Activate validation'));}
                    else {
                        echo $this->Form->end(__('Deactivate validation')); }
            ?>
    </div>
  </div>

 <div class="confbox">
    <div class="conf">
      <h3><?php echo __('Geo position'); ?></h3>
        <p><?php echo __('Change the source GPS position of the generated connections'); ?></p>
           <?php  echo $this->Html->image('geoposition.gif'); ?>
	<br />
          
        <?php echo $this->Form->create('GPSposition',array( 'url' => array('controller' => 'configurations', 'action' => 'geoposition', 'label' => false)));
               echo $this->Form->input('long',  array('label' =>__('Long'), 'maxlength'=> 10, 'size' => '10', 'value' => $long));
                echo $this->Form->input('lat',   array('label' =>__('Lat'), 'maxlength'=> 10, 'size' => '10', 'value' => $lat));
                echo $this->Form->end(__('Change'));
         ?>
    </div>
  </div>

  <div class="confbox">
    <div class="conf">
      <h3><?php echo __('Data wrapper'); ?></h3>
      <p align=justify><?php echo __('Option for creating an index of decoded info at /opt/xplico/lastdata.txt to use it with thertiary applicacions.'); ?></p>
      <br />
     <?php if ($isLastdataActivated == 0) {
             echo $this->Html->image('enable.gif');
             echo "<br />";
             echo __('Data wrapper').' <b>'.__('not activated').'</b>';
             $changeDWStatusTo = "1";       }
           else {
             echo $this->Html->image('disable.gif');
             echo "<br />";
             echo __('Data wrapper').' <b>'.__('activated').'</b>';
             $changeDWStatusTo = "0";        }
          ?>
	<br />

      <?php echo $this->Form->create(null, array('url' => array ('controller' => 'configurations', 'action' => 'lastdatatogle')));?>
      <?php echo $this->Form->hidden('lastdata', array('value'=>$changeDWStatusTo));?>
      <?php if ($isLastdataActivated == 0) {
               echo $this->Form->end(__("Activate wrapper"));}
            else {
               echo $this->Form->end(__("Deactivate wrapper")); }
	?>
      

    </div>
  </div>

  <div class="confbox">
    <div class="conf">
      <h3><?php echo __('Dissectors'); ?></h3>
        <p><?php echo __('Enable and disable each dissector'); ?></p>
        <?php echo $this->Html->link(__('Dissectors Manager'), '/configurations/dissectors'); ?>
    </div>
  </div>

  <div class="cline"> </div>

  <div class="confbox">
    <div class="conf confsmall">
      <h3><?php echo __("Xplico\'s status"); ?></h3>
	<?php
         if ($isXplicoRunning == 0) {
                        echo $this->Html->image('delete_64.png');
                        echo "<br />";
                        echo __("Xplico system is not running");
                        $changeStatusTo = "1";       }
                else {
                        echo $this->Html->image('tick_64.png');
                        echo "<br />";
                        echo __("Xplico system is running");
                        $changeStatusTo = "0";        }
         ?>
   </div>
  </div>

  <div class="confbox">
    <div class="conf confsmall">
      <h3><?php echo __('Storage'); ?></h3>
        <p align="justify"><?php echo __('Storage data base'); ?></p>
        <br />
           <?php  echo $this->Html->image('database.gif'); ?>
        <p align="center"><b><?php echo $dbstorage; ?></b></p>
    </div>
  </div>

 <div class="confbox">
    <div class="conf confsmall">
  	 <h3><?php echo __('Max PCAP size'); ?></h3>
  	 <?php echo __('Current max accepted size of PCAPs: '); ?>
	 <?php echo $maxSizePCAP ?>MB.

	   <p align="center">
           <?php echo $this->Html->image('pcapsize	.gif'); ?>
	    <br /><br />
	    <?php echo __('To change this maximum size, check'); ?> <a href="http://wiki.xplico.org/doku.php?id=faq">this</a>.
	   </p>
    </div>
  </div>

 <div class="confbox">
    <div class="conf confsmall">
      <h3><?php echo __('Xplico update'); ?></h3>
	<p align="justify"><?php echo __('Xplico will check if there is a newer version'); ?><br /></p>
           <?php  echo $this->Html->image('update.gif'); ?>

	   <?php echo $this->Form->create('checkupdates', array( 'url' => array('controller' => 'configurations', 'action' => 'checkupdates', 'label' => false)));
		echo '<div class="cline"> </div>';
      		echo $this->Form->end( __('Check new versions')); ?>
	<br />
    </div>
 </div>
  <div class="cline"> </div>

<fieldset>	  	
	<legend><?php echo __('Software versions'); ?></legend>
	<TABLE BORDER=0>
	   <?php	
	        echo "<tr>";
		  echo "<td>";
		  echo __("Xplico version");
		  echo "<td>";
		  echo $xplicoVersion;  
		  echo "<td>";
		  echo __("Dema version");
		  echo "<td>";
		  echo $demaVersion;  
		  echo "<td>";
		  echo __("Sqlite version");
		  echo "<td>";
		  echo $sqliteVersion; 
		echo "<tr>";
		  echo "<td>";
		  echo __("Cakephp version");
		  echo "<td>";
		  echo $cakephpVersion;  
		  echo "<td>";
		  echo __("Apache version");
		  echo "<td>";
		  echo $apacheVersion;
		  echo "<td>";
		  echo __("PHP version");
		  echo "<td>";
		  echo $PHPVersion;
		echo "<tr>";
		  echo "<td>";
		  echo __("Tshark version");
		  echo "<td>";
		  echo $TsharkVersion; 
		  echo "<td>";
		  echo __("tcpdump version");
		  echo "<td>";
		  echo $tcpdumpVersion;  
		  echo "<td>";
		  echo __("Videosnarf version");
		  echo "<td>";
		  echo $videosnarfVersion;
		echo "<tr>";
		  echo "<td>";
		  echo __("Lame version");
		  echo "<td>";
		  echo $lameVersion;
		  echo "<td>";
		  echo __("GNU/Linux version");
		  echo "<td>";
		  echo $GNULinuxVersion; 
		  echo "<td>";
		  echo __("Kernel version");
		  echo "<td>";
		  echo $KernelVersion;
		echo "<tr>";
		  echo "<td>";
		  echo __("Libpcap version");
		  echo "<td>";
		  echo $LibPCAPVersion;	
		  echo "<td>";
		  echo __("Xplico Alerts");
		  echo "<td>";
		  echo $xplicoAlertsVersion;  
		  echo "<td>";
		  echo __("Sox version");
		  echo "<td>";
		  echo $SoxVersion;
		echo "<tr>";
		  echo "<td>";
		  echo __("Recode version");
		  echo "<td>";
		  echo $RecodeVersion; 
		  echo "<td>";
		  echo __("Python plugin");
		  echo "<td>";
		  echo $PythonVersion;
		  echo "<td>";
		  echo __("GhostPDL version");
		  echo "<td>";
		  echo "$GhostPDLVersion";
		echo "<tr>";
		  echo "<td>";
		  echo __("GeoIP version");
		  echo "<td>";
		  echo $GeoIPVersion;
		  echo "<td>";
		  echo "";
		  echo "<td>";
		  echo "";
		  echo "<td>";
		  echo "<td>";

		echo "</TABLE>";
	?>		

</fieldset>

</div>
</center>
