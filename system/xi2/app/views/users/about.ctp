<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<div class="generic centered sol">
<h1><b>Xplico is a Network Forensic Analysis Tool (NFAT)</b></h1>
<br />
<p>
The goal of Xplico is extract from an internet traffic capture the applications data contained.
<br />
<br />
The supported functionality, dissectors and target CPUs are listed in the <b><?php echo $html->link('status', 'http://www.xplico.org/status') ?> </b> page from web site.
<br />
<br />
This product includes GeoLite data created by MaxMind, available from <b><?php echo $html->link('http://www.maxmind.com/', 'http://www.maxmind.com/') ?></b>.
<br />
<br />
Many thanks to <b><?php echo $html->link('Open Flash Chart', 'http://teethgrinder.co.uk/open-flash-chart-2/')?></b> team for their work.
</p>
</div>

  <div class="sol">
    <h3><?php __('Rules'); ?></h3>
    <ul>
      <li><strong><?php __('All data will be deleted at'); ?>: 00:00 GMT</strong></li>
      <li><?php __('Max pcap file size'); ?>: <strong>5MB</strong>.<?php __(' Larger files will be rejected. There is no limit on how many packets the capture file contains.'); ?></li>
      <li><strong><?php __('Total pcap size limit'); ?>: 10MB</strong></li>
      <li><?php __("While the decoded data are not shared, we make no claims that your data is not viewable by other users. For now, if you want to protect sensitive data in your capture files, don't use the free XplicoDemo service."); ?></li>
      <li><?php __("We recommend using Firefox 3.x, Safari 4.x or greater, or Google Chrome."); ?>
    </ul> 
  </div>