#! /usr/bin/env python3
#
# Copyright (c) 2010-2011 Gianluca Costa
#
# Author: Gianluca Costa, 2011
#      g.costa@xplico.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#



import string
import sys
import os
import getopt
import time
import io
import json
import urllib.parse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.generator import Generator

ver = "1.1"

# copyright and license
def xcopyright(argv):
    nam = argv[0].rfind('/') + 1
    name = argv[0][nam:]
    print(name+" version "+ver+"""

Copyright (c) 2013 Gianluca Costa. All Rights Reserved.
Binary licensed under the following Creative Commons license: Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0).
NOTE: If you need a written commercial license that's available on request from its author: xplico@capanalysis.net
""")


# usage manual
def usage(argv):
    xcopyright(argv)
    nam = argv[0].rfind('/') + 1
    name = argv[0][nam:]
    
    print("""
    Usage: """+name+""" [-s]  <alice_web_mail_address> <alice_web_mail> <alice_web_mail_body> <output_file>
       <alice_web_mail_address>: email address
       <alice_web_mail>: email or email header file
       <alice_web_mail_body>: email body file
       <output_file>: file in mwmail (manipulator) format
       -s: if set the email is sent, otherwise is received
    """)

# save the pessage
def save_msg(msg, out_file):
    eml = MIMEMultipart()
    info_file = open(out_file, "w")
    # convert strings 
    for key, val in msg.items() :
        if key != 'parts' :
            msg[key] = val.encode('raw_unicode_escape', 'ignore').decode('ascii', 'ignore')
    
    # write info extracted
    if msg['subject']:
        info_file.write("SUBJECT:"+msg['subject']+"\n")
    if msg['from']:
        info_file.write("FROM:"+msg['from']+"\n")
    if msg['to']:
        info_file.write("TO:"+msg['to']+"\n")
    if msg['cc'] != "":
        info_file.write("CC:"+msg['cc']+"\n")
    if msg['messageid'] != "":
        info_file.write("MESSAGEID:"+msg['messageid']+"\n")
    if msg['received'] != "":
        info_file.write("RECEIVED:"+msg['received']+"\n")
    if msg['sent'] != "":
        info_file.write("SENT:"+msg['sent']+"\n")
        
    # mime
    eml['Subject'] = msg['subject']
    eml['From'] = msg['from']
    eml['To'] = msg['to']
    if msg['sent'] != "":
        eml['Date'] = msg['sent']
    eml['Message-Id'] = msg['messageid']
    if msg['cc'] != "":
        eml['Cc'] = msg['cc']
    j = 0
    
    for part in msg['parts']:
        prt = '%d' % j
        out_file_part = out_file+"_"+prt
        if part['txt'] != "" and part['html'] != "":
            msg = MIMEMultipart('alternative')
            text_file = open(out_file_part+".txt","w")
            text_file.write(part['txt'])
            text_file.close()
            info_file.write("PART_"+prt+":"+out_file_part+".txt"+"\n")
            part1 = MIMEText(part['txt'], 'plain')
            html_file = open(out_file_part+".html","w")
            html_file.write(part['html'])
            html_file.close()
            info_file.write("HTML_"+prt+":"+out_file_part+".html"+"\n")
            # convert
            os.system("recode html.. "+out_file_part+".html")
            html_file = open(out_file_part+".html", 'r')
            html_page = html_file.read()
            html_file.close()
            part2 = MIMEText(html_page, 'html')
            msg.attach(part1)
            msg.attach(part2)
            eml.attach(msg)
        elif part['txt'] != "":
            text_file = open(out_file_part+".txt","w")
            text_file.write(part['txt'])
            text_file.close()
            info_file.write("PART_"+prt+":"+out_file_part+".txt"+"\n")
            #eml
            eml_part = MIMEText(part['txt'], 'plain')
            eml.attach(eml_part)
        elif part['html'] != "":
            html_file = open(out_file_part+".html","w")
            html_file.write(part['html'])
            html_file.close()
            info_file.write("HTML_"+prt+":"+out_file_part+".html"+"\n")
            # convert
            os.system("recode html.. "+out_file_part+".html")
            html_file = open(out_file_part+".html", 'r')
            html_page = html_file.read()
            html_file.close()
            #eml
            eml_part = MIMEText(html_page, 'html')
            eml.attach(eml_part)
        if part['filename'] != "":
            info_file.write("FILENAME_"+prt+":"+part['filename']+"\n")
        j += 1
        
    # eml file
    fp = io.StringIO()
    g = Generator(fp, mangle_from_=False, maxheaderlen=60)
    g.flatten(eml)
    eml_file = open(out_file+".eml","w")
    eml_file.write(fp.getvalue())
    eml_file.close()
    info_file.write("EML:"+out_file+".eml"+"\n")
    info_file.close()


def JConver(raw):
    raw = raw.replace('": \'', '": "')
    raw = raw.replace('\',"', '","')
    return raw

    
# parse header: to, from, cc and subject
def parse_header_message(toaddress, msgfile_header):
    msg = {} # message
    fp = open(msgfile_header)
    jformat = fp.read()
    fp.close()
    # json decoding
    jformat = JConver(jformat)
    tmp = json.loads(jformat)
    
    # subject
    msg['subject'] = tmp['emailheaders'][0]['subject']
    # from
    msg['from'] = tmp['emailheaders'][0]['from']
    # to
    msg['to'] = toaddress
    # date
    msg['sent'] = tmp['emailheaders'][0]['sdate']
    msg['received'] = tmp['emailheaders'][0]['rdate']
    msg['cc'] = tmp['emailheaders'][0]['cc']
    msg['messageid'] = tmp['emailheaders'][0]['compid']
    return msg


# parse body: message
def parse_body_message(msg, msgfile_body):
    parts = [] # parts
    fp = open(msgfile_body, 'rb')
    eformat = fp.read().decode("ascii", 'ignore')
    fp.close()
    prt = {}
    prt['txt'] = ''
    prt['html'] = eformat
    prt['filename'] = ""
    parts.append(prt)
    msg['parts'] = parts
    return msg
    
        
# decode mail received
def alice_received(email_address, msgfile_header, msgfile_body, out_file):
    # extract mail data
    msg = parse_header_message(email_address, msgfile_header)
    msg = parse_body_message(msg, msgfile_body)
    # output file
    msg_out_file = out_file + '_0'
    save_msg(msg, msg_out_file)
    

def parse_sent_message(email_address, msgfile):
    msg = {} # message
    fp = open(msgfile, 'rb')
    eformat = fp.read().decode("ascii", 'ignore')
    fp.close()
    tmp = urllib.parse.parse_qs(urllib.parse.urlparse(eformat).path)
    # subject
    msg['subject'] = tmp['subject'][0]
    # from
    msg['from'] = email_address
    # to
    msg['to'] = tmp['to_recipients'][0]
    try:
        msg['cc'] = tmp['cc_recipients'][0]
    except:
        msg['cc'] = ''
    msg['messageid'] = tmp['draft_id'][0]
    msg['sent'] = ''
    msg['received'] = ''
    
    parts = [] # parts
    prt = {}
    prt['txt'] = ''
    prt['html'] = "<html><head></head><body>"+tmp['message'][0]+"</body></html>"
    prt['filename'] = ""
    parts.append(prt)
    msg['parts'] = parts
    return msg
    
        
# decode mail sent
def alice_sent(email_address, msgfile, out_file):
    msg = parse_sent_message(email_address, msgfile)
    # output file
    msg_out_file = out_file + '_0'
    save_msg(msg, msg_out_file)
    
    
def alice_main(argv):
    try:
        opts, args = getopt.getopt(argv, "sh")
    except getopt.GetoptError:
        usage(sys.argv)
        sys.exit(2)

    mobile = False
    
    # process options
    for o, a in opts:
        # help
        if o in ('-h'):
            usage(sys.argv)
            sys.exit(0)
            
        # sent
        if o in ('-s'):
            if len(args) != 3:
                usage(sys.argv)
                sys.exit(0)
            alice_sent(args[0], args[1], args[2])
            sys.exit(0)
    
    # received
    if len(args) != 4:
        usage(sys.argv)
        sys.exit(2)
    alice_received(args[0], args[1], args[2], args[3])
    

if __name__ == '__main__':
    alice_main(sys.argv[1:])
