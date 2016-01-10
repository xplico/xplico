<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<h2>Case or Listening Point (POL)</h2>
<p>
A Case or POL represents a Listening Point, namely, the point of the net from which the data to be codified are captured/taken. To add a new Case it is sufficient to select from the menu on the left the voce NewCase and to enter in the form which will be used the name of the new Case or a reference name.
</p>
<h2>Listening Session (SOL)</h2>
<p>
Every  Case can be composed by an arbitrary group of Listening Sessions (SOL) representing the time subdivision (hours, days, weeks) according to which the captures of  the Listening Points have occurred.
There's no limit in the number of SOL  which may form a Case, the only condition in the creation of a new SOL is that it should contain captures which are temporarily successive to those of the preceding SOL. To create/add a SOL it is sufficient to select AddSol from the menu on the left and to enter the name of the new SOL in the form.<br/>
Approaching to the first SOL in the list, it is possible to introduce/enter the data to be captured or codified, a single file at a time (in pcap format). Whenever a new file is entered, the codification  starts after 15 seconds. After the codification has been started, it will be possible to have access to the encoded data through the menu on the left. For every Listening session it is possible to introduce an arbitrary number of pcap files, the only rule which should be followed when entering a capture file is that every pcap which is being introduced should contain data following the previous ones.
</p>
<h2>Menu</h2>
<p>
The menu is composed by the following items: Email, Image and Sip.
By selecting Email it will be possible to visualize the encoded emails and to have access to their contents.<br/>
By selecting Image it will be possible to visualize all the images which passed with the HTTP 'protocol'.<br/>
By selecting SIP it will be possible to view all VOIP calls performed with the SIP 'protocol'.
</p>
<h2>Info.xml</h2>
<p>
The info.xml file is 'present' for every codified content and gives all the information concerning the codification of the content from the 'capture' file to its IP and PORT.
</p>
<h2>Firefox Browser</h2>
<p>
The Xplico Interface has been realized for Firefox, therefore we suggest you to use this.
</p>
<h2>GeoIP</h2>
<p>
This product includes GeoLite data created by MaxMind, available from <b><?php echo $html->link('http://www.maxmind.com/', 'http://www.maxmind.com/') ?></b>.
</p>
<h2>Dns Graphs</h2>
<p>
The graphs are made with <b><?php echo $html->link('Open Flash Chart', 'http://teethgrinder.co.uk/open-flash-chart-2/')?></b>
</p>