#! /usr/bin/env python3
#
# Copyright (c) 2010-2011 Gianluca Costa
#
# Author: Gianluca Costa, 2010
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
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.generator import Generator

ver = "1.1"

# copyright and license
def xcopyright(argv):
    nam = argv[0].rfind('/') + 1
    name = argv[0][nam:]
    
    print(name+" version "+ver+"""
    Part of Xplico Internet Traffic Decoder (NFAT).
    See http://www.xplico.org for more information.

    Copyright 2007-2011 Gianluca Costa & Andrea de Franceschi and contributors.
    This is free software; see the source for copying conditions. There is NO
    warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
""")

    
# usage manual
def usage(argv):
    xcopyright(argv)
    nam = argv[0].rfind('/') + 1
    name = argv[0][nam:]
    
    print("""
    Usage: """+name+""" [-s] <yahoo_web_mail> <output_file>
       <yahoo_web_mail>: web mail sent or received
       <output_file>: file in mwmail (manipulator) format
       -s : if set the email is sent, otherwise is received
    """)


# tag data extraction
def data_tag(data, tag):
    start = data.find('<'+tag+'>')
    if start == -1:
        start = data.find('<'+tag+' ')
        if start != -1:
            start = data[start:].find('>') + 1 + start
    else:
        start_ext = data.find('<'+tag+' ')
        if start_ext == -1:
            start += len('<'+tag+'>')
        elif start_ext > start:
            start += len('<'+tag+'>')
        else:
            start = data[start_ext:].find('>') + 1 + start_ext

    if start == -1:
        return ""
    end = data.find('</'+tag+'>')
    if end >= start:
        return data[start:end]
    return ""


# find next tag
def next_tag(data, tag, i):
    end = 0
    j = 0
    while True:
        end = data.find('</'+tag+'>')
        if end == -1:
            return ""
        end += len('</'+tag+'>')
        data = data[end:]
        if j == i:
            return data
        j += 1


# tag attributes
def tag_attr(data, tag):
    attrib = {}
    start = data.find('<'+tag+' ')
    if start != -1:
        start += len('<'+tag+' ')
        end = data[start:].find('>') + start
        all_attr = data[start:end]
        attr = all_attr.split(" ")
        for at in attr:
            sub = at.split('=')
            attrib[sub[0]] = sub[1]
    return attrib


# decodig email address
def address(mail):
    m = ['', '']
    # name
    start = mail.find('<name>') + len("<name>")
    end = mail.find('</name>')
    if end > start:
        m[0] = mail[start:end]
    # email
    start = mail.find('<email>') + len("<email>")
    end = mail.find('</email>')
    m[1] = mail[start:end]
    return m


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
    
    
# decoding mail sent
def yahoo_sent(msgfile, out_file):
    mto = [] # emails address for to
    mfrom = [] # emails address for from
    mcc = [] # emails address for cc
    # read file
    fp = open(msgfile)
    eformat = fp.read()
    fp.close()
    # find extract main data
    data = data_tag(eformat, 'message')
    # extract subject
    subject = data_tag(data, 'subject')
    # extract to
    tmp = data
    i = 0
    while True:
        to = data_tag(tmp, 'to')
        if to != "":
            mto.append(address(to))
            tmp = next_tag(data, 'to', i)
            i += 1
        else:
            break
    # extract from
    tmp = data
    i = 0
    while True:
        frm = data_tag(tmp, 'from')
        if frm != "":
            mfrom.append(address(frm))
            tmp = next_tag(data, 'from', i)
            i += 1
        else:
            break
    # extract cc
    tmp = data
    i = 0
    while True:
        cc = data_tag(tmp, 'cc')
        if cc != "":
            mcc.append(address(cc))
            tmp = next_tag(data, 'cc', i)
            i += 1
        else:
            break
    # extract simplebody
    simplebody = data_tag(data, 'simplebody')
    # extract text
    text = data_tag(simplebody, 'text')
    # extract html
    html = data_tag(simplebody, 'html')
    
    # to string
    tos = ""
    for elem in mto:
        if tos != "":
            tos += ","
        tos = tos + elem[0] + " <" + elem[1] + ">"
    # from string
    froms = ""
    for elem in mfrom:
        if froms != "":
            froms += ";"
        froms = froms + elem[0] + " <" + elem[1] + ">"
    # cc string
    ccs = ""
    for elem in mcc:
        if ccs != "":
            ccs += ","
        ccs = ccs + elem[0] + " <" + elem[1] + ">"
        
    # write info extracted
    out_file +="_0"
    info_file = open(out_file, "w")
    info_file.write("SUBJECT:"+subject+"\n")
    info_file.write("FROM:"+froms+"\n")
    info_file.write("TO:"+tos+"\n")
    if ccs != "":
        info_file.write("CC:"+ccs+"\n")
    # write text file
    if text != "":
        text_file = open(out_file+".txt","w")
        text_file.write(text)
        text_file.close()
        info_file.write("PART_0:"+out_file+".txt"+"\n")
    # write html file
    if html != "":
        html_file = open(out_file+".html","w")
        html_file.write(html)
        html_file.close()
        info_file.write("HTML_0:"+out_file+".html"+"\n")
        # convert
        os.system("recode html.. "+out_file+".html")
        html_file = open(out_file+".html", 'r')
        html_page = html_file.read()
        html_file.close()
    
    # eml file
    # Create message container - the correct MIME type is multipart/alternative.
    compose = False
    if text != "" and html != "":
        msg = MIMEMultipart('alternative')
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html_page, 'html')
        msg.attach(part1)
        msg.attach(part2)
        compose = True
    elif text != "":
        msg = MIMEText(text, 'plain')
        compose = True
    elif html != "":
        msg = MIMEText(html_page, 'html')
        compose = True

    if compose:
        msg['Subject'] = subject
        msg['From'] = froms
        msg['To'] = tos
        if ccs != "":
            msg['Cc'] = ccs
            
        fp = io.StringIO()
        g = Generator(fp, mangle_from_=False, maxheaderlen=60)
        g.flatten(msg) 
        eml_file = open(out_file+".eml","w")
        eml_file.write(fp.getvalue())
        eml_file.close()
        info_file.write("EML:"+out_file+".eml"+"\n")
        info_file.close()


def parse_rec_message(message):
    msg = {} # message
    mto = [] # emails address for to
    mfrom = [] # emails address for from
    mcc = [] # emails address for cc
    mbcc = [] # emails address for bcc
    parts = [] # parts
    sdate = "" # sent date
    rdate = "" # received date
    # extract message ID
    mid = data_tag(message, 'mid')
    # real message ID
    rmid = data_tag(message, 'messageId')
    # extract received and sent date
    unix_time = data_tag(message, 'receivedDate')
    if unix_time != "":
        unix_time = float(unix_time)
        #rdate = time.asctime(time.gmtime(unix_time))
        rdate = datetime.datetime.fromtimestamp(unix_time).strftime('%Y-%m-%d %H:%M:%S')
    unix_time = data_tag(message, 'sentDate')
    if unix_time != "":
        unix_time = float(unix_time)
        #sdate = time.asctime(time.gmtime(unix_time))
        sdate = datetime.datetime.fromtimestamp(unix_time).strftime('%Y-%m-%d %H:%M:%S')
    # extract subject
    subject = data_tag(message, 'subject')
    # extract to
    tmp = message
    i = 0
    while True:
        to = data_tag(tmp, 'to')
        if to != "":
            mto.append(address(to))
            tmp = next_tag(message, 'to', i)
            i += 1
        else:
            break
    # extract from
    tmp = message
    i = 0
    while True:
        frm = data_tag(tmp, 'from')
        if frm != "":
            mfrom.append(address(frm))
            tmp = next_tag(message, 'from', i)
            i += 1
        else:
            break
    # extract cc
    tmp = message
    i = 0
    while True:
        cc = data_tag(tmp, 'cc')
        if cc != "":
            mcc.append(address(cc))
            tmp = next_tag(message, 'cc', i)
            i += 1
        else:
            break
    # parts (email body)
    tmp = message
    i = 0
    while True:
        prt = {}
        part = data_tag(tmp, 'part')
        if part != "":
            attrib = tag_attr(tmp, 'part')
            prt['txt'] = ""
            prt['html'] = ""
            prt['filename'] = ""
            if attrib['type'] == '"text"':
                if attrib['subtype'] == '"html"':
                    prt['html'] =  data_tag(part, 'text')
                else:
                    prt['txt'] = data_tag(part, 'text')
            if attrib['filename'] != '""':
                prt['filename'] = attrib['filename']
            parts.append(prt)
            tmp = next_tag(message, 'part', i)
            i += 1
        else:
            break

    ## compose message
    # to string
    tos = ""
    for elem in mto:
        if tos != "":
            tos += ","
        tos = tos + elem[0] + " <" + elem[1] + ">"
    msg['to'] = tos
    
    # from string
    froms = ""
    for elem in mfrom:
        if froms != "":
            froms += ";"
        froms = froms + elem[0] + " <" + elem[1] + ">"
    msg['from'] = froms
    # cc string
    ccs = ""
    for elem in mcc:
        if ccs != "":
            ccs += ","
        ccs = ccs + elem[0] + " <" + elem[1] + ">"
    msg['cc'] = ccs
    # parts
    msg['parts'] = parts
    # info
    rmid = rmid.replace('&lt;', '<') 
    msg['messageid'] = rmid.replace('&gt;', '>')
    msg['subject'] = subject
    msg['received'] = rdate
    msg['sent'] = sdate
    return msg
    

    
# decode mail received
def yahoo_received(msgfile, out_file):
    # read file
    fp = open(msgfile)
    eformat = fp.read()
    fp.close()
    tmp = eformat
    i = 0
    while True:
    # find extract main data
        data = data_tag(tmp, 'message')
        if data != "":
            msg = parse_rec_message(data)
    # new output file
            msg_out_file = out_file + '_%d' % i
            save_msg(msg, msg_out_file)
            tmp = next_tag(eformat, 'message', i)
            i += 1
        else:
            break

    
def yahoo_main(argv):
    try:
        opts, args = getopt.getopt(argv, "sh")
    except getopt.GetoptError:
        usage(sys.argv)
        sys.exit(2)
    
    # process options
    for o, a in opts:
        # help
        if o in ("-h"):
            usage(sys.argv)
            sys.exit(0)
        # sent
        if o in ("-s"):
            if len(args) != 2:
                usage(sys.argv)
                sys.exit(2)
            yahoo_sent(args[0], args[1])
            sys.exit(0)
        
    # received
    if len(args) != 2:
        usage(sys.argv)
        sys.exit(2)
    
    yahoo_received(args[0], args[1])
    

if __name__ == '__main__':
    yahoo_main(sys.argv[1:])
