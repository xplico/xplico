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
      <th><?php __('Dissector'); ?></th>
      <th><?php __('Status'); ?></th>
      <th><?php __('Dissector'); ?></th>
      <th><?php __('Status'); ?></th>
  </tr>
  <tr>
      <td><?php __('Pcap'); ?></td>
      <td><?php echo $html->link($dissectors['pcapf'], '/configurations/dissectors/pcapf'); ?></td>
      <td><?php __('Xplico Case'); ?></td>
      <td><?php echo $html->link($dissectors['pol'], '/configurations/dissectors/pol'); ?></td>
  </tr>
  <tr>
      <td><?php __('Ethernet'); ?></td>
      <td><?php echo $html->link($dissectors['eth'], '/configurations/dissectors/eth'); ?></td>
      <td><?php __('PPPoE'); ?></td>
      <td><?php echo $html->link($dissectors['pppoe'], '/configurations/dissectors/pppoe'); ?></td>
  </tr>
  <tr>
      <td><?php __('PPP'); ?></td>
      <td><?php echo $html->link($dissectors['ppp'], '/configurations/dissectors/ppp'); ?></td>
      <td><?php __('RADIOTAP'); ?></td>
      <td><?php echo $html->link($dissectors['radiotap'], '/configurations/dissectors/radiotap'); ?></td>
  </tr>
  <tr>
      <td><?php __('IP'); ?></td>
      <td><?php echo $html->link($dissectors['ip'], '/configurations/dissectors/ip'); ?></td>
      <td><?php __('IPv6'); ?></td>
      <td><?php echo $html->link($dissectors['ipv6'], '/configurations/dissectors/ipv6'); ?></td>
  </tr>
  <tr>
      <td><?php __('TCP'); ?></td>
      <td><?php echo $html->link($dissectors['tcp'], '/configurations/dissectors/tcp'); ?></td>
      <td><?php __('UDP'); ?></td>
      <td><?php echo $html->link($dissectors['udp'], '/configurations/dissectors/udp'); ?></td>
  </tr>
  <tr>
      <td><?php __('HTTP'); ?></td>
      <td><?php echo $html->link($dissectors['http'], '/configurations/dissectors/http'); ?></td>
      <td><?php __('POP'); ?></td>
      <td><?php echo $html->link($dissectors['pop'], '/configurations/dissectors/pop'); ?></td>
  </tr>
  <tr>
      <td><?php __('IMAP'); ?></td>
      <td><?php echo $html->link($dissectors['imap'], '/configurations/dissectors/imap'); ?></td>
      <td><?php __('SMTP'); ?></td>
      <td><?php echo $html->link($dissectors['smtp'], '/configurations/dissectors/smtp'); ?></td>
  </tr>
  <tr>
      <td><?php __('HTTP file transfer'); ?></td>
      <td><?php echo $html->link($dissectors['httpfd'], '/configurations/dissectors/httpfd'); ?></td>
      <td><?php __('SIP'); ?></td>
      <td><?php echo $html->link($dissectors['sip'], '/configurations/dissectors/sip'); ?></td>
  </tr>
  <tr>
      <td><?php __('RTP'); ?></td>
      <td><?php echo $html->link($dissectors['rtp'], '/configurations/dissectors/rtp'); ?></td>
      <td><?php __('RTCP'); ?></td>
      <td><?php echo $html->link($dissectors['rtcp'], '/configurations/dissectors/rtcp'); ?></td>
  </tr>
  <tr>
      <td><?php __('SDP'); ?></td>
      <td><?php echo $html->link($dissectors['sdp'], '/configurations/dissectors/sdp'); ?></td>
      <td><?php __('L2TP'); ?></td>
      <td><?php echo $html->link($dissectors['l2tp'], '/configurations/dissectors/l2tp'); ?></td>
  </tr>
  <tr>
      <td><?php __('VLAN'); ?></td>
      <td><?php echo $html->link($dissectors['vlan'], '/configurations/dissectors/vlan'); ?></td>
      <td><?php __('FTP'); ?></td>
      <td><?php echo $html->link($dissectors['ftp'], '/configurations/dissectors/ftp'); ?></td>
  </tr>
  <tr>
      <td><?php __('DNS'); ?></td>
      <td><?php echo $html->link($dissectors['dns'], '/configurations/dissectors/dns'); ?></td>
      <td><?php __('ICMP'); ?></td>
      <td><?php echo $html->link($dissectors['icmp'], '/configurations/dissectors/icmp'); ?></td>
  </tr>
  <tr>
      <td><?php __('NNTP'); ?></td>
      <td><?php echo $html->link($dissectors['nntp'], '/configurations/dissectors/nntp'); ?></td>
      <td><?php __('IRC'); ?></td>
      <td><?php echo $html->link($dissectors['irc'], '/configurations/dissectors/irc'); ?></td>
  </tr>
  <tr>
      <td><?php __('IPP'); ?></td>
      <td><?php echo $html->link($dissectors['ipp'], '/configurations/dissectors/ipp'); ?></td>
      <td><?php __('PJL'); ?></td>
      <td><?php echo $html->link($dissectors['pjl'], '/configurations/dissectors/pjl'); ?></td>
  </tr>
  <tr>
      <td><?php __('MMS'); ?></td>
      <td><?php echo $html->link($dissectors['mms'], '/configurations/dissectors/mms'); ?></td>
      <td><?php __('SLL'); ?></td>
      <td><?php echo $html->link($dissectors['sll'], '/configurations/dissectors/sll'); ?></td>
  </tr>
  <tr>
      <td><?php __('TFTP'); ?></td>
      <td><?php echo $html->link($dissectors['tftp'], '/configurations/dissectors/tftp'); ?></td>
      <td><?php __('IEEE80211'); ?></td>
      <td><?php echo $html->link($dissectors['ieee80211'], '/configurations/dissectors/ieee80211'); ?></td>
  </tr>
  <tr>
      <td><?php __('LLC'); ?></td>
      <td><?php echo $html->link($dissectors['llc'], '/configurations/dissectors/llc'); ?></td>
      <td><?php __('Facebook Web chat'); ?></td>
      <td><?php echo $html->link($dissectors['fbwchat'], '/configurations/dissectors/fbwchat'); ?></td>
  </tr>
  <tr>
      <td><?php __('TELNET'); ?></td>
      <td><?php echo $html->link($dissectors['telnet'], '/configurations/dissectors/telnet'); ?></td>
      <td><?php __('Web mail'); ?></td>
      <td><?php echo $html->link($dissectors['webmail'], '/configurations/dissectors/webmail'); ?></td>
  </tr>
  <tr>
      <td><?php __('ARP'); ?></td>
      <td><?php echo $html->link($dissectors['arp'], '/configurations/dissectors/arp'); ?></td>
      <td><?php __('Paltalk Express'); ?></td>
      <td><?php echo $html->link($dissectors['paltalk_exp'], '/configurations/dissectors/paltalk_exp'); ?></td>
  </tr>
  <tr>
      <td><?php __('MSN'); ?></td>
      <td><?php echo $html->link($dissectors['msn'], '/configurations/dissectors/msn'); ?></td>
      <td><?php __('Paltalk'); ?></td>
      <td><?php echo $html->link($dissectors['paltalk'], '/configurations/dissectors/paltalk'); ?></td>
  </tr>
  <tr>
      <td><?php __('TCP L7p'); ?></td>
      <td><?php echo $html->link($dissectors['tcp_grb'], '/configurations/dissectors/tcp_grb'); ?></td>
      <td><?php __('UDP L7p'); ?></td>
      <td><?php echo $html->link($dissectors['udp_grb'], '/configurations/dissectors/udp_grb'); ?></td>
  </tr>
  <tr>
      <td><?php __('PPI'); ?></td>
      <td><?php echo $html->link($dissectors['ppi'], '/configurations/dissectors/ppi'); ?></td>
      <td><?php __('Syslog'); ?></td>
      <td><?php echo $html->link($dissectors['syslog'], '/configurations/dissectors/syslog'); ?></td>
  </tr>
  <tr>
      <td><?php __('PRISM'); ?></td>
      <td><?php echo $html->link($dissectors['prism'], '/configurations/dissectors/prism'); ?></td>
      <td><?php __('NULL'); ?></td>
      <td><?php echo $html->link($dissectors['null'], '/configurations/dissectors/null'); ?></td>
  </tr>
  <tr>
      <td><?php __('chdlc'); ?></td>
      <td><?php echo $html->link($dissectors['chdlc'], '/configurations/dissectors/chdlc'); ?></td>
      <td><?php __('Web Yahoo! MSG'); ?></td>
      <td><?php echo $html->link($dissectors['webymsg'], '/configurations/dissectors/webymsg'); ?></td>
  </tr>
  <tr>
      <td><?php __('mgcp'); ?></td>
      <td><?php echo $html->link($dissectors['mgcp'], '/configurations/dissectors/mgcp'); ?></td>
      <td><?php __('whatsapp'); ?></td>
      <td><?php echo $html->link($dissectors['whatsapp'], '/configurations/dissectors/whatsapp'); ?></td>
  </tr>
</table>
</div>
