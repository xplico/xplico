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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.generator import Generator

ver = "1.0"

# copyright and license
def xcopyright(argv):
    nam = argv[0].rfind('/') + 1
    name = argv[0][nam:]
    print(name+" version "+ver+"""

Copyright (c) 2011 Gianluca Costa & Andrea de Franceschi. All Rights Reserved.
Binary licensed under the following Creative Commons license: Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0).
NOTE: If you need a written commercial license that's available on request from its author: xplico@capanalysis.net
""")


# usage manual
def usage(argv):
    xcopyright(argv)
    nam = argv[0].rfind('/') + 1
    name = argv[0][nam:]
    
    print("""
    Usage: """+name+""" [-m] [-s] <libero_web_mail> [<libero_web_mail_body>] <output_file>
       <libero_web_mail>: email or email header file (for new webmail version)
       <libero_web_mail_body>: email body file (only for new webmail version)
       <output_file>: file in mwmail (manipulator) format
       -m: webmail libero mobile
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


# delete tag
def delete_tags(data):
    meta = ''
    end = 0
    offset = 0
    start = data.find('<')
    while start != -1 :
        start += end
        meta += data[offset:start]
        end = data[start:].find('>')
        if end == -1 :
            break
        end += start
        offset = end + 1
        start = data[end:].find('<')
    if end != -1:
        meta += data[offset:]
    meta = meta.strip()
    return meta


# parse header: to, from, cc and subject
def parse_header_message(msgfile_header):
    msg = {} # message
    fp = open(msgfile_header)
    eformat = fp.read();
    fp.close()
    tmp = eformat
    # subject
    start = tmp.find('Oggetto:')
    if start == -1 :
        msg['subject'] = ''
    else :
        start += len('Oggetto:')
        end = tmp[start:].find('<tr>') + start
        subject =delete_tags(tmp[start:end])
        msg['subject'] = subject
    # from
    start = tmp.find('Da:')
    if start == -1 :
        msg['from'] = ''
    else :
        start += len('Da:')
        end = tmp[start:].find('<tr>') + start
        eadd = delete_tags(tmp[start:end])
        eadd = eadd.replace('&lt;', '<') 
        msg['from'] = eadd.replace('&gt;', '>')
    # to
    start = tmp.find('A:')
    if start == -1 :
        msg['to'] = ''
    else :
        start += len('A:')
        end = tmp[start:].find('<tr>') + start
        eadd = delete_tags(tmp[start:end])
        eadd = eadd.replace('&lt;', '<') 
        eadd = eadd.replace('&gt;', '>')
        eadd = eadd.replace('&#', '')
        msg['to'] = eadd.replace(';', ',')
    # date
    start = tmp.find('Data:')
    if start == -1 :
        msg['sent'] = ''
        msg['received'] = ''
    else :
        start += len('Data:')
        end = tmp[start:].find('</table>') + start        
        end2 = tmp[start:].find('<tr')
        if end2 != -1 :
            end2 += start
            if end2 < end :
                end = end2
        msg['sent'] = delete_tags(tmp[start:end])
        msg['received'] = ''
    msg['cc'] = ''
    msg['messageid'] = ''
    return msg


# parse body: message
def parse_body_message(msg, msgfile_body):
    parts = [] # parts
    fp = open(msgfile_body)
    eformat = fp.read();
    fp.close()
    tmp = eformat
    # body message
    start = tmp.find('id="onlyMessage"')
    if start == -1 :
        return msg
    start += tmp[start:].find('>') + 1
    end = tmp[start:].find('hackFixResize()') + start
    message = tmp[start:end]
    end = message.rfind('</div>')
    if end != -1 :
        message = message[:end]
    message = message.strip()
    prt = {}
    prt['txt'] = ''
    prt['html'] = message
    prt['filename'] = ""
    parts.append(prt)
    msg['parts'] = parts
    return msg


def mobile_libero(msgfile):
    msg = {} # message
    parts = [] # parts
    fp = open(msgfile)
    eformat = fp.read();
    fp.close()
    tmp = eformat
    # subject
    start = tmp.find('div_intestazione_read')
    if start == -1 :
        return msg
    start += tmp[start:].find('>') + 1
    end = tmp.find('div_allegati_read')
    header = tmp[start:end]
    tmp = delete_tags(header)
    # subject
    start = tmp.find('Oggetto:')
    if start == -1 :
        msg['subject'] = ''
    else :
        start += len('Oggetto:')
        subject = tmp[start:]
        msg['subject'] = subject
    # from
    start = tmp.find('Da:')
    if start == -1 :
        msg['from'] = ''
    else :
        start += len('Da:')
        end = tmp[start:].find('Data:') + start
        eadd = tmp[start:end]
        eadd = eadd.replace('&lt;', '<') 
        msg['from'] = eadd.replace('&gt;', '>')
    # to
    start = tmp.find('A:')
    if start == -1 :
        msg['to'] = ''
    else :
        start += len('A:')
        end = tmp[start:].find('Oggetto:') + start
        eadd = tmp[start:end]
        eadd = eadd.replace('&lt;', '<') 
        eadd = eadd.replace('&gt;', '>')
        eadd = eadd.replace('&#', '')
        msg['to'] = eadd.replace(';', ',')
    # date
    start = tmp.find('Data:')
    if start == -1 :
        msg['sent'] = ''
        msg['received'] = ''
    else :
        start += len('Data:')
        end = tmp[start:].find('A:') + start
        msg['sent'] = tmp[start:end]
        msg['received'] = ''
    msg['cc'] = ''
    msg['messageid'] = ''
    # body message
    tmp = eformat
    start = tmp.find('div_testo_read')
    if start == -1 :
        return msg
    start += tmp[start:].find('>') + 1
    end = tmp.find('l-footer')
    if end > start :
        body = tmp[start:end]
        end = body.rfind('<div')
        body = body[:end]
    else :
        body = tmp[start:]
    prt = {}
    prt['txt'] = ''
    prt['html'] = body
    prt['filename'] = ""
    parts.append(prt)
    msg['parts'] = parts
    return msg
        


# decode mail received
def libero_received(msgfile_header, msgfile_body, out_file):
    # extract mail data
    msg = parse_header_message(msgfile_header)
    msg = parse_body_message(msg, msgfile_body)
    # output file
    msg_out_file = out_file + '_0'
    save_msg(msg, msg_out_file)
    

# decode mobile mail received
def libero_mobile_received(msgfile, out_file):
    # extract mail data
    msg = mobile_libero(msgfile)
    # output file
    msg_out_file = out_file + '_0'
    save_msg(msg, msg_out_file)
    

def libero_main(argv):
    try:
        opts, args = getopt.getopt(argv, "shm")
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
        # mobile
        if o in ('-m') :
            mobile = True
        
        # sent
        if o in ('-s'):
            if len(args) != 2:
                usage(sys.argv)
                sys.exit(2)
            libero_sent(args[0], args[1])
            sys.exit(0)
    
    # received
    if mobile :
        if len(args) != 2:
            usage(sys.argv)
            sys.exit(2)
        libero_mobile_received(args[0], args[1])
        
    else :
        if len(args) != 3:
            usage(sys.argv)
            sys.exit(2)
        libero_received(args[0], args[1], args[2])
    

if __name__ == '__main__':
    libero_main(sys.argv[1:])
