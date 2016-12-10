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
import html.parser
import urllib.parse
import re
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
    Usage: """+name+""" [-s <yahoo_req_body>] <yahoo_mail> <output_file>
       <yahoo_mail>: email in json format (POST body response)
       <output_file>: file in mwmail (manipulator) format
       <yahoo_req_body>: body of HTTP POST request
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
            try:
                if part['charset'] != '':
                    part2.set_charset(part['charset'])
            except:
                pass
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
            try:
                if part['charset'] != '':
                    eml_part.set_charset(part['charset'])
            except:
                pass
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
    try:
        header = msg_raw['header']
    except:
        return False

    msg['from'] = header['from']['name']+'<'+header['from']['email']+'>'
    msg['to'] = ''
    for addr in header['to']:
        msg['to'] = msg['to'] + addr['name']+'<'+addr['email']+'>,'
    msg['to'] = msg['to'][:-1]
    msg['subject'] = header['subject']
    msg['sent'] = datetime.datetime.fromtimestamp(header['sentDate']).strftime('%Y-%m-%d %H:%M:%S')
    msg['received'] = datetime.datetime.fromtimestamp(header['receivedDate']).strftime('%Y-%m-%d %H:%M:%S')
    try:
        msg['replyto'] = ''
        for addr in header['replyto']:
            msg['replyto'] = msg['replyto'] + addr['name']+'<'+addr['email']+'>,'
        msg['replyto'] = msg['replyto'][:-1]
    except:
        msg['replyto'] = msg['from']
    msg['cc'] = ''
    for addr in header['cc']:
        msg['cc'] = msg['cc'] + addr['name']+'<'+addr['email']+'>,'
    msg['cc'] = msg['cc'][:-1]
    msg['bcc'] = ''
    for addr in header['bcc']:
        msg['bcc'] = msg['bcc'] + addr['name']+'<'+addr['email']+'>,'
    msg['bcc'] = msg['bcc'][:-1]
    parts = [] # parts
    for part in msg_raw['part']:
        prt = {}
        try:
            body = part['text']
            body = body.replace('\"', '"')
            body = body.replace('\/', "/")
            if part['subtype'] == 'html':
                prt['txt'] = ''
                prt['html'] = body
                prt['filename'] = ''
            else:
                prt['txt'] = body
                prt['html'] = ''
                prt['filename'] = ''
            try:
                prt['charset'] = part['typeParams'].replace('charset=', '')
            except:
                prt['charset'] = ''
            parts.append(prt)
        except:
            pass
        
    msg['parts'] = parts
    return msg


def JConver(raw):
    return raw
    

def JConverSent(raw):
    return raw


# decode mail received
def mail_received(msgfile, out_file):
    fp = open(msgfile)
    jformat = fp.read()
    fp.close()
    # json decoding
    jformat = JConver(jformat)
    tmp = json.loads(jformat)
    # verifica presenza della struttura a messaggi
    try:
        messages = tmp['result']['message']
    except:
        return
    i = 0
    for rmsg in messages:
        msg = decode_json_msg(rmsg)
        if msg != False:
            msg_out_file = out_file + '_' + str(i)
            i = i + 1
            save_msg(msg, msg_out_file)
        else:
            print('Email non estratta')
        


def decode_sent_msg(msg_raw, data):
    msg = {} # message
    msg['messageid'] = data['result']['mid']
    msg['sent'] = ''
    msg['received'] = ''
    msg['subject'] = msg_raw['subject']
    msg['from'] = msg_raw['from']['name']+'<'+msg_raw['from']['email']+'>'
    msg['to'] = ''
    for addr in msg_raw['to']:
        msg['to'] = msg['to'] + addr['name']+'<'+addr['email']+'>,'
    msg['to'] = msg['to'][:-1]
    try:
        msg['replyto'] = ''
        for addr in msg_raw['replyto']:
            msg['replyto'] = msg['replyto'] + addr['name']+'<'+addr['email']+'>,'
        msg['replyto'] = msg['replyto'][:-1]
    except:
        msg['replyto'] = msg['from']
    msg['cc'] = ''
    for addr in msg_raw['cc']:
        msg['cc'] = msg['cc'] + addr['name']+'<'+addr['email']+'>,'
    msg['cc'] = msg['cc'][:-1]
    msg['bcc'] = ''
    for addr in msg_raw['bcc']:
        msg['bcc'] = msg['bcc'] + addr['name']+'<'+addr['email']+'>,'
    msg['bcc'] = msg['bcc'][:-1]
    
    parts = [] # parts
    prt = {}
    try:
        prt['txt'] = msg_raw['simplebody']['text']
    except:
        prt['txt'] = ''
    try:
        prt['html'] = msg_raw['simplebody']['html']
    except:
        prt['html'] = ''
        
    prt['html'] = prt['html'].replace('\"', '"')
    prt['html'] = prt['html'].replace('\\', "\\")
    prt['filename'] = ""
    parts.append(prt)
    msg['parts'] = parts

    return msg


def CheckSent(req):
    try:
        if req['method'] == 'SendMessage':
            return True
        else:
            return False
    except:
        return False


def mail_sent(msgfile, confirm, out_file):
    fp = open(msgfile)
    rformat = fp.read()
    fp.close()
    fp = open(confirm)
    jidmsg = fp.read()
    fp.close()
    # verifica se e' un draft o meno
    jidmsg = JConverSent(jidmsg)
    jidmsg = json.loads(jidmsg)
    smail = json.loads(rformat)
    if CheckSent(smail):
        dmsg = smail['params'][0]['message']
        msg = decode_sent_msg(dmsg, jidmsg)
        # output file
        i = 0
        msg_out_file = out_file + '_' + str(i)
        i = i + 1
        save_msg(msg, msg_out_file)
    

def ymain(argv):
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
    ymain(sys.argv[1:])
