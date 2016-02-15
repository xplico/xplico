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
    Usage: """+name+""" [-s <gmail_req_hdr> <gmail_req_body>] <gmail_mail> <output_file>
       <gmail_mail>: email in json format (POST body response)
       <output_file>: file in mwmail (manipulator) format
       <gmail_req_hdr>: header of HTTP POST request
       <gmail_req_body>: body of HTTP POST request
       -s: if set the email is sent, otherwise is received
       
    """)
    

def GmailUnescape(string):
    """ This function reverses gmail strings
    """
    string = string.replace(r"\'","'")
    string = string.replace(r'\"','"')
    string = re.sub(r"\\u(....)",lambda m: chr(int(m.group(1),16)), string)
    string = re.sub(r"\\>",">", string)
    string = re.sub(r"&#([^;]+);",lambda m: chr(int(m.group(1),10)), string)
    string = urllib.parse.unquote(string)

    return string


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
    msg['messageid'] = ''
    message = msg_raw[13]
    if type(message) == int:
        return False
    try:
        msg['from'] = GmailUnescape(msg_raw[4])
    except IndexError:
        return False
    try:
        to = message[1]
        if type(to) == list:
            to = ",".join(to)
        msg['to'] =GmailUnescape(to)
    except IndexError:
        return False
    try:
        msg['subject'] = GmailUnescape(message[5])
    except IndexError:
        return False
    try:
        msg['sent'] = GmailUnescape(message[10])
    except IndexError:
        return False
    msg['received'] = msg['sent']

    msg['replyto'] = ''
    msg['cc'] = ''
    msg['bcc'] = ''
    try:
        body = GmailUnescape(message[6])
    except IndexError:
        return False
    parts = [] # parts
    prt = {}
    prt['txt'] = ''
    prt['html'] = body
    prt['filename'] = ""
    parts.append(prt)
    msg['parts'] = parts
    return msg


def JConver(raw):
    # convert to json
    raw = raw.replace('while(1);', '')
    raw = raw.replace(',,', ',0,')
    raw = raw.replace(',,', ',0,')
    p1 = raw.find("\n],'")
    if p1 != -1:
        partstart = raw[:p1]
        partend = raw[p1:]
        partend = partend.replace("'", '"')
        assemple = partstart+partend
        return assemple
    else:
        return raw
    

def JConverSent(raw):
    # convert to json
    raw = raw.replace('while(1);', '')
    p1 = raw.find("[")
    size = int(raw[:p1]) - 1
    raw = raw[p1:p1+size]
    raw = raw.replace(',,', ',0,')
    raw = raw.replace(',,', ',0,')
    return raw


# decode mail received
def mail_received(msgfile, out_file):
    fp = open(msgfile, encoding='utf-8')
    jformat = fp.read();
    fp.close()
    # json decoding
    jformat = JConver(jformat)
    tmp = json.loads(jformat)
    i = 0
    for hmsg in tmp[0]:
        if hmsg[0] == 'ms':
            msg = decode_json_msg(hmsg)
            if msg != False:
                msg_out_file = out_file + '_' + str(i)
                i = i + 1
                save_msg(msg, msg_out_file)
            else:
                print('Email non estratta')
        


def decode_sent_msg(msg_raw, data, login):
    msg = {} # message
    try:
        msg['messageid'] = msg_raw['draft']
    except:
        msg['messageid'] = ''
    msg['sent'] = ''
    for d in data:
        try:
            if d[0] == 'st':
                msg['sent'] = datetime.datetime.fromtimestamp(d[1]).strftime('%Y-%m-%d %H:%M:%S')
                #msg['sent'] = time.asctime(time.gmtime(d[1]))
                break
        except:
            pass
    msg['received'] = ''
    msg['subject'] = msg_raw['subject']
    msg['from'] = login
    msg['replyto'] = ''
    msg['to'] = msg_raw['to']
    msg['cc'] = msg_raw['cc']
    msg['bcc'] = msg_raw['bcc']
    parts = [] # parts
    try:
        body = msg_raw['body'].replace("\'", "'")
        body = body.replace('\\', "\\")
        prt = {}
        if msg_raw['ishtml'] == '1':
            prt['txt'] = ''
            prt['html'] = body
        else:
            prt['txt'] = body
            prt['html'] = ''
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


def CheckSent(sentfile):
    try:
        # da completare se serve
        return True
    except:
        return False


def EmailExtra(header):
    p1 = header.find('gmailchat=')
    if p1 != -1:
        email = header[p1+10:]
        p2 = email.find('/')
        p3 = email.find(';')
        if p2 != -1 and p2 < p3:
            return email[:p2]
        else:
            return email[:p3]
    else:
        return 'unknown'


def mail_sent(header, msgfile, confirm, out_file):
    fp = open(header)
    header = fp.read();
    fp.close()
    fp = open(msgfile)
    rformat = fp.read();
    fp.close()
    fp = open(confirm)
    jidmsg = fp.read();
    fp.close()
    # estrazione email
    email = EmailExtra(header)
    # verifica se e' un draft o meno
    jidmsg = JConverSent(jidmsg)
    jidmsg = json.loads(jidmsg)
    if CheckSent(jidmsg):
        dmsg = dict()
        for i in rformat.split('&'):
            s = i.split('=')
            if len(s) == 2:
                dmsg[s[0]] = urllib.parse.unquote(s[1])
            elif len(s) == 1:
                dmsg[s[0]] = ''
        msg = decode_sent_msg(dmsg, jidmsg, email)
        # output file
        i = 0
        msg_out_file = out_file + '_' + str(i)
        i = i + 1
        save_msg(msg, msg_out_file)
    

def gmain(argv):
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
            if len(args) != 4:
                usage(sys.argv)
                sys.exit(2)
            mail_sent(args[0], args[1], args[2], args[3])
            sys.exit(0)
    
    # received
    if len(args) != 2:
        usage(sys.argv)
        sys.exit(2)
    mail_received(args[0], args[1])
    

if __name__ == '__main__':
    gmain(sys.argv[1:])
