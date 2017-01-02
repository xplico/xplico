<!--
Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
 Version: MPL 1.1/GPL 2.0/LGPL 2.1
-->
<script>
$(function() {
    $('td:contains("On") a').css('color', 'green')
     .css('font-weight', 'bold');
    $('td:contains("Off") a').css('color', 'red')
     .css('font-weight', 'bold');
});
</script>


<div class="generic">

<table id="messagelist" summary="Message list" cellspacing="0" table-layout: auto>
  <tr>
      <th><?php echo __('Dissector'); ?></th>
      <th><?php echo __('Status'); ?></th>
      <th><?php echo __('Dissector'); ?></th>
      <th><?php echo __('Status'); ?></th>
  </tr>
  <tr>
      <td><?php echo __('Pcap'); ?></td>
      <td><?php echo $this->Html->link($dissectors['pcapf'], '/configurations/dissectors/pcapf'); ?></td>
      <td><?php echo __('Xplico Case'); ?></td>
      <td><?php echo $this->Html->link($dissectors['pol'], '/configurations/dissectors/pol'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('Ethernet'); ?></td>
      <td><?php echo $this->Html->link($dissectors['eth'], '/configurations/dissectors/eth'); ?></td>
      <td><?php echo __('PPPoE'); ?></td>
      <td><?php echo $this->Html->link($dissectors['pppoe'], '/configurations/dissectors/pppoe'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('PPP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['ppp'], '/configurations/dissectors/ppp'); ?></td>
      <td><?php echo __('RADIOTAP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['radiotap'], '/configurations/dissectors/radiotap'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('IP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['ip'], '/configurations/dissectors/ip'); ?></td>
      <td><?php echo __('IPv6'); ?></td>
      <td><?php echo $this->Html->link($dissectors['ipv6'], '/configurations/dissectors/ipv6'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('TCP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['tcp'], '/configurations/dissectors/tcp'); ?></td>
      <td><?php echo __('UDP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['udp'], '/configurations/dissectors/udp'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('HTTP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['http'], '/configurations/dissectors/http'); ?></td>
      <td><?php echo __('POP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['pop'], '/configurations/dissectors/pop'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('IMAP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['imap'], '/configurations/dissectors/imap'); ?></td>
      <td><?php echo __('SMTP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['smtp'], '/configurations/dissectors/smtp'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('HTTP file transfer'); ?></td>
      <td><?php echo $this->Html->link($dissectors['httpfd'], '/configurations/dissectors/httpfd'); ?></td>
      <td><?php echo __('SIP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['sip'], '/configurations/dissectors/sip'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('RTP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['rtp'], '/configurations/dissectors/rtp'); ?></td>
      <td><?php echo __('RTCP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['rtcp'], '/configurations/dissectors/rtcp'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('SDP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['sdp'], '/configurations/dissectors/sdp'); ?></td>
      <td><?php echo __('L2TP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['l2tp'], '/configurations/dissectors/l2tp'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('VLAN'); ?></td>
      <td><?php echo $this->Html->link($dissectors['vlan'], '/configurations/dissectors/vlan'); ?></td>
      <td><?php echo __('FTP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['ftp'], '/configurations/dissectors/ftp'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('DNS'); ?></td>
      <td><?php echo $this->Html->link($dissectors['dns'], '/configurations/dissectors/dns'); ?></td>
      <td><?php echo __('ICMP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['icmp'], '/configurations/dissectors/icmp'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('NNTP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['nntp'], '/configurations/dissectors/nntp'); ?></td>
      <td><?php echo __('IRC'); ?></td>
      <td><?php echo $this->Html->link($dissectors['irc'], '/configurations/dissectors/irc'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('IPP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['ipp'], '/configurations/dissectors/ipp'); ?></td>
      <td><?php echo __('PJL'); ?></td>
      <td><?php echo $this->Html->link($dissectors['pjl'], '/configurations/dissectors/pjl'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('MMS'); ?></td>
      <td><?php echo $this->Html->link($dissectors['mms'], '/configurations/dissectors/mms'); ?></td>
      <td><?php echo __('SLL'); ?></td>
      <td><?php echo $this->Html->link($dissectors['sll'], '/configurations/dissectors/sll'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('TFTP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['tftp'], '/configurations/dissectors/tftp'); ?></td>
      <td><?php echo __('IEEE80211'); ?></td>
      <td><?php echo $this->Html->link($dissectors['ieee80211'], '/configurations/dissectors/ieee80211'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('LLC'); ?></td>
      <td><?php echo $this->Html->link($dissectors['llc'], '/configurations/dissectors/llc'); ?></td>
      <td><?php echo __('Facebook Web chat'); ?></td>
      <td><?php echo $this->Html->link($dissectors['fbwchat'], '/configurations/dissectors/fbwchat'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('TELNET'); ?></td>
      <td><?php echo $this->Html->link($dissectors['telnet'], '/configurations/dissectors/telnet'); ?></td>
      <td><?php echo __('Web mail'); ?></td>
      <td><?php echo $this->Html->link($dissectors['webmail'], '/configurations/dissectors/webmail'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('ARP'); ?></td>
      <td><?php echo $this->Html->link($dissectors['arp'], '/configurations/dissectors/arp'); ?></td>
      <td><?php echo __('Paltalk Express'); ?></td>
      <td><?php echo $this->Html->link($dissectors['paltalk_exp'], '/configurations/dissectors/paltalk_exp'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('MSN'); ?></td>
      <td><?php echo $this->Html->link($dissectors['msn'], '/configurations/dissectors/msn'); ?></td>
      <td><?php echo __('Paltalk'); ?></td>
      <td><?php echo $this->Html->link($dissectors['paltalk'], '/configurations/dissectors/paltalk'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('TCP L7p'); ?></td>
      <td><?php echo $this->Html->link($dissectors['tcp_grb'], '/configurations/dissectors/tcp_grb'); ?></td>
      <td><?php echo __('UDP L7p'); ?></td>
      <td><?php echo $this->Html->link($dissectors['udp_grb'], '/configurations/dissectors/udp_grb'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('PPI'); ?></td>
      <td><?php echo $this->Html->link($dissectors['ppi'], '/configurations/dissectors/ppi'); ?></td>
      <td><?php echo __('Syslog'); ?></td>
      <td><?php echo $this->Html->link($dissectors['syslog'], '/configurations/dissectors/syslog'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('PRISM'); ?></td>
      <td><?php echo $this->Html->link($dissectors['prism'], '/configurations/dissectors/prism'); ?></td>
      <td><?php echo __('NULL'); ?></td>
      <td><?php echo $this->Html->link($dissectors['null'], '/configurations/dissectors/null'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('chdlc'); ?></td>
      <td><?php echo $this->Html->link($dissectors['chdlc'], '/configurations/dissectors/chdlc'); ?></td>
      <td><?php echo __('Web Yahoo! MSG'); ?></td>
      <td><?php echo $this->Html->link($dissectors['webymsg'], '/configurations/dissectors/webymsg'); ?></td>
  </tr>
  <tr>
      <td><?php echo __('mgcp'); ?></td>
      <td><?php echo $this->Html->link($dissectors['mgcp'], '/configurations/dissectors/mgcp'); ?></td>
      <td><?php echo __('whatsapp'); ?></td>
      <td><?php echo $this->Html->link($dissectors['whatsapp'], '/configurations/dissectors/whatsapp'); ?></td>
  </tr>
</table>
</div>
