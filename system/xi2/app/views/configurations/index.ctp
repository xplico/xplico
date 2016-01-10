<!--
Copyright:  Carlos Gacimartín <cgacimartin@gmail.com>
    Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<center>
<div class="configurations form" >
<fieldset>
	<legend><b><?php __('Xplico Control pane'); ?></b></legend>
 <div class="cline"> </div>

  <div class="confbox">
    <div class="conf">
      <h3><?php __('Checksum validation'); ?></h3>
	<p><?php __('Option to enable/disable checksum analysis. Without checksum verification more information will be decoded, but it is not legally reliable, as those packets may have been sent by any other host.'); ?>
	</p>
	<br />
         <?php if ($isChecksumValidationActivated == 0) {
                        echo $html->image('enable.gif');
                        echo "<br />";
                        echo __('Validating checksums:', true).'<b>'. __('OFF', true).'</b>';
                        $changeChecksumValidationStatusTo = "1";       }
                else {
                        echo $html->image('disable.gif');
                        echo "<br />";
                        echo __('Validating checksum:', true).'<b>'.__('ON', true).'</b>';
                        $changeChecksumValidationStatusTo = "0";        }
                ?>
	  <br />

	    <?php echo $form->create(null, array ('controller' => 'configuration', 'action' => 'checksumtogle'));?>
            <?php echo $form->hidden('checksumStatus', array('value'=>$changeChecksumValidationStatusTo));?>
            <?php if ($isChecksumValidationActivated == 0) {
                        echo $form->end(__('Activate validation', true));}
                    else {
                        echo $form->end(__('Deactivate validation', true)); }
                ?>
    </div>
  </div>

 <div class="confbox">
    <div class="conf">
      <h3><?php __('Geo position'); ?></h3>
        <p><?php __('Change the source GPS position of the generated connections'); ?></p>
           <?php  echo $html->image('geoposition.gif'); ?>
	<br />
          
        <?php echo $form->create('GPSposition',array( 'url' => array('controller' => 'configurations', 'action' => 'geoposition', 'label' => false)));
               echo $form->input('long',  array('label' =>__('Long', true), 'maxlength'=> 10, 'size' => '10', 'value' => $long));
                echo $form->input('lat',   array('label' =>__('Lat', true), 'maxlength'=> 10, 'size' => '10', 'value' => $lat));
                echo $form->end(__('Change', true));
         ?>
    </div>
  </div>

  <div class="confbox">
    <div class="conf">
      <h3><?php __('Data wrapper'); ?></h3>
      <p align=justify><?php __('Option for creating an index of decoded info at /opt/xplico/lastdata.txt to use it with thertiary applicacions.'); ?></p>
      <br />
     <?php if ($isLastdataActivated == 0) {
             echo $html->image('enable.gif');
             echo "<br />";
             echo __('Data wrapper', true).'<b>'.__('not activated', true).'</b>';
             $changeDWStatusTo = "1";       }
           else {
             echo $html->image('disable.gif');
             echo "<br />";
             echo __('Data wrapper', true).'<b>'.__('activated', true).'</b>';
             $changeDWStatusTo = "0";        }
          ?>
	<br />

      <?php echo $form->create(null, array ('controller' => 'configuration', 'action' => 'lastdatatogle'));?>
      <?php echo $form->hidden('lastdata', array('value'=>$changeDWStatusTo));?>
      <?php if ($isLastdataActivated == 0) {
               echo $form->end(__("Activate wrapper", true));}
            else {
               echo $form->end(__("Deactivate wrapper", true)); }
	?>
      

    </div>
  </div>

  <div class="confbox">
    <div class="conf">
      <h3><?php __('Dissectors'); ?></h3>
        <p><?php __('Enable and disable each dissector'); ?></p>
        <?php echo $html->link(__('Dissectors Manager', true), '/configurations/dissectors'); ?>
    </div>
  </div>

  <div class="cline"> </div>

  <div class="confbox">
    <div class="conf confsmall">
      <h3><?php __("Xplico\'s status"); ?></h3>
	<?php
         if ($isXplicoRunning == 0) {
                        echo $html->image('delete_64.png');
                        echo "<br />";
                        echo __("Xplico system is not running", true);
                        $changeStatusTo = "1";       }
                else {
                        echo $html->image('tick_64.png');
                        echo "<br />";
                        echo __("Xplico system is running", true);
                        $changeStatusTo = "0";        }
         ?>
   </div>
  </div>

  <div class="confbox">
    <div class="conf confsmall">
      <h3><?php __('Storage'); ?></h3>
        <p align="justify"><?php __('Storage data base'); ?></p>
        <br />
           <?php  echo $html->image('database.gif'); ?>
        <p align="center"><b><?php echo $dbstorage; ?></b></p>
    </div>
  </div>

 <div class="confbox">
    <div class="conf confsmall">
  	 <h3><?php __('Max PCAP size'); ?></h3>
  	 <?php __('Current max accepted size of PCAPs: '); ?>
	 <?php echo $maxSizePCAP ?>MB.

	   <p align="center">
           <?php echo $html->image('pcapsize	.gif'); ?>
	    <br /><br />
	    <?php __('To change this maximum size, check'); ?> <a href="http://wiki.xplico.org/doku.php?id=faq">this</a>.
	   </p>
    </div>
  </div>

 <div class="confbox">
    <div class="conf confsmall">
      <h3><?php __('Xplico update'); ?></h3>
	<p align="justify"><?php __('Xplico will check if there is a newer version'); ?><br /></p>
           <?php  echo $html->image('update.gif'); ?>

	   <?php echo $form->create('checkupdates', array( 'url' => array('controller' => 'configurations', 'action' => 'checkupdates', 'label' => false)));
		echo '<div class="cline"> </div>';
      		echo $form->end( __('Check new versions', true)); ?>
	<br />
    </div>
 </div>
  <div class="cline"> </div>

<fieldset>	  	
	<legend><?php __('Software versions'); ?></legend>
	<TABLE BORDER=0>
	   <?php	
	        echo "<tr>";
		  echo "<td>";
		  echo __("Xplico version", true);
		  echo "<td>";
		  echo $xplicoVersion;  
		  echo "<td>";
		  echo __("Dema version", true);
		  echo "<td>";
		  echo $demaVersion;  
		  echo "<td>";
		  echo __("Sqlite version", true);
		  echo "<td>";
		  echo $sqliteVersion; 
		echo "<tr>";
		  echo "<td>";
		  echo __("Cakephp version", true);
		  echo "<td>";
		  echo $cakephpVersion;  
		  echo "<td>";
		  echo __("Apache version", true);
		  echo "<td>";
		  echo $apacheVersion;
		  echo "<td>";
		  echo __("PHP version", true);
		  echo "<td>";
		  echo $PHPVersion;
		echo "<tr>";
		  echo "<td>";
		  echo __("Tshark version", true);
		  echo "<td>";
		  echo $TsharkVersion; 
		  echo "<td>";
		  echo __("tcpdump version", true);
		  echo "<td>";
		  echo $tcpdumpVersion;  
		  echo "<td>";
		  echo __("Videosnarf version", true);
		  echo "<td>";
		  echo $videosnarfVersion;
		echo "<tr>";
		  echo "<td>";
		  echo __("Lame version", true);
		  echo "<td>";
		  echo $lameVersion;
		  echo "<td>";
		  echo __("GNU/Linux version", true);
		  echo "<td>";
		  echo $GNULinuxVersion; 
		  echo "<td>";
		  echo __("Kernel version", true);
		  echo "<td>";
		  echo $KernelVersion;
		echo "<tr>";
		  echo "<td>";
		  echo __("Libpcap version", true);
		  echo "<td>";
		  echo $LibPCAPVersion;	
		  echo "<td>";
		  echo __("Xplico Alerts", true);
		  echo "<td>";
		  echo $xplicoAlertsVersion;  
		  echo "<td>";
		  echo __("Sox version", true);
		  echo "<td>";
		  echo $SoxVersion;
		echo "<tr>";
		  echo "<td>";
		  echo __("Recode version", true);
		  echo "<td>";
		  echo $RecodeVersion; 
		  echo "<td>";
		  echo __("Python plugin", true);
		  echo "<td>";
		  echo $PythonVersion;
		  echo "<td>";
		  echo __("GhostPDL version", true);
		  echo "<td>";
		  echo "$GhostPDLVersion";
		echo "<tr>";
		  echo "<td>";
		  echo __("GeoIP version", true);
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
