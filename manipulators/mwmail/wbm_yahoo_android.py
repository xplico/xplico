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
import datetime
#import html.parser
import urllib.parse
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
    Usage: """+name+""" [-s <yahoo_android_request_body>] <yahoo_android_mail> <output_file>
       <yahoo_android_mail>: email in json format (POST body response)
       <output_file>: file in mwmail (manipulator) format
       <yahoo_android_request_body>: body of HTTP POST request
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


def decode_json_msg(msg_raw):
    msg = {} # message
    msg['messageid'] = msg_raw['mid']
    msg['sent'] = datetime.datetime.fromtimestamp(msg_raw['header']['sentDate']).strftime('%Y-%m-%d %H:%M:%S')
    msg['received'] = datetime.datetime.fromtimestamp(msg_raw['header']['receivedDate']).strftime('%Y-%m-%d %H:%M:%S')
    msg['subject'] = msg_raw['header']['subject']
    msg['from'] = '<'+msg_raw['header']['from']['email']+'>'+msg_raw['header']['from']['name']
    rep_addr = ''
    for m in msg_raw['header']['replyto']:
        rep_addr = rep_addr+'<'+m['email']+'>'+m['name']+','
    msg['replyto'] = rep_addr[:-1]
    to_addr = ''
    for m in msg_raw['header']['to']:
        to_addr = to_addr+'<'+m['email']+'>'+m['name']+','
    msg['to'] = to_addr[:-1]
    cc_addr = ''
    for m in msg_raw['header']['cc']:
        cc_addr = cc_addr+'<'+m['email']+'>'+m['name']+','
    msg['cc'] = cc_addr[:-1]
    bcc_addr = ''
    for m in msg_raw['header']['bcc']:
        bcc_addr = bcc_addr+'<'+m['email']+'>'+m['name']+','
    msg['bcc'] = bcc_addr[:-1]
    ctype = msg_raw['content-type']
    body = msg_raw['body'].replace('\"', '"')
    body = body.replace('\\', "\\")
    parts = [] # parts
    if ctype.find('html') != -1:
        prt = {}
        prt['txt'] = ''
        prt['html'] = body
        prt['filename'] = ""
        parts.append(prt)
        msg['parts'] = parts
    else:
        prt = {}
        prt['txt'] = body
        prt['html'] = ''
        prt['filename'] = ""
        parts.append(prt)
        msg['parts'] = parts
    return msg


# decode mail received
def mail_received(msgfile, out_file):
    fp = open(msgfile)
    jformat = fp.read();
    fp.close()
    # json decoding
    tmp = json.loads(jformat)
    try:
        messages = tmp['data']['messages']
    except:
        messages = []
    # short info
    try:
        minfo = tmp['data']['minfos']['minfo']['new']
        id_message = tmp['data']['minfos']['meta']['message']
    except:
        minfo = []
            
    i = 0
    for msg_raw in messages:
        msg = decode_json_msg(msg_raw)
        # output file
        msg_out_file = out_file + '_' + str(i)
        i = i + 1
        save_msg(msg, msg_out_file)

    for msg_raw in minfo:
        try:
            msg = decode_json_msg(msg_raw[id_message])
            # output file
            msg_out_file = out_file + '_' + str(i)
            i = i + 1
            save_msg(msg, msg_out_file)
        except:
            pass
        

def decode_sent_msg(msg_raw, idmsg):
    msg = {} # message
    try:
        msg['messageid'] = idmsg['data']['mid']
    except:
        msg['messageid'] = ''
    msg['sent'] = ''
    msg['received'] = ''
    msg['subject'] = msg_raw['message']['subject'].replace('+', ' ')
    msg['from'] = '<'+msg_raw['message']['from']['email']+'>'+msg_raw['message']['from']['name'].replace('+', ' ')
    msg['replyto'] = ''
    to_addr = ''
    for m in msg_raw['message']['to']:
        to_addr = to_addr+'<'+m['email']+'>'+m['name'].replace('+', ' ')+','
    msg['to'] = to_addr[:-1]
    cc_addr = ''
    for m in msg_raw['message']['cc']:
        cc_addr = cc_addr+'<'+m['email']+'>'+m['name'].replace('+', ' ')+','
    msg['cc'] = cc_addr[:-1]
    bcc_addr = ''
    for m in msg_raw['message']['cc']:
        bcc_addr = bcc_addr+'<'+m['email']+'>'+m['name'].replace('+', ' ')+','
    msg['bcc'] = bcc_addr[:-1]
    parts = [] # parts

    try:
        body = msg_raw['message']['simplebody']['html'].replace('\"', '"')
        body = body.replace('\\', "\\")
        body = body.replace('+', " ")
        prt = {}
        prt['txt'] = ''
        prt['html'] = body
        prt['filename'] = ""
        parts.append(prt)
        msg['parts'] = parts
    except:
        prt = {}
        prt['txt'] = ''
        prt['html'] = ''
        prt['filename'] = ""
        parts.append(prt)
        msg['parts'] = parts

    return msg

def mail_sent(msgfile, id_file, out_file):
    fp = open(msgfile)
    rformat = fp.read();
    fp.close()
    fp = open(id_file)
    jidmsg = fp.read();
    fp.close()
    
    param = urllib.parse.unquote(rformat)
    pstart = param.find('&params=')
    if pstart != -1:
        pstart = pstart + len('&params=')
        tmp = json.loads(param[pstart:])
        idmsg = json.loads(jidmsg)
        msg = decode_sent_msg(tmp, idmsg)
        # output file
        i = 0
        msg_out_file = out_file + '_' + str(i)
        i = i + 1
        save_msg(msg, msg_out_file)
    

def yahoo_android_main(argv):
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
                sys.exit(2)
            mail_sent(args[0], args[1], args[2])
            sys.exit(0)
    
    # received
    if len(args) != 2:
        usage(sys.argv)
        sys.exit(2)
    mail_received(args[0], args[1])
    

if __name__ == '__main__':
    yahoo_android_main(sys.argv[1:])
