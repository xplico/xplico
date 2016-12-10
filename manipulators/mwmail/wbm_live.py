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
import io
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
    Usage: """+name+""" [-s] <hotmail_web_mail> <output_file>
       <hotmail_web_mail>: web mail sent or received
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
        return None
    end = data.find('</'+tag+'>')
    if end >= start:
        return data[start:end]
    return None


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


# find context for 'from' 'to' 'sent'
def LiveContext(data):
    context = None
    # to
    if data.startswith('Da:') or data.startswith('From:') or data.startswith('À :')  or data.startswith('De:'): # Italian, English, French, Spanish
        context = 'From'
    elif data.startswith('A:') or data.startswith('To:') or data.startswith('De :') or data.startswith('Para:') : # Italian, English, French, Spanish
        context = 'To'
    elif data.startswith('Inviato:') or data.startswith('Sent:') or data.startswith('Envoyé :') or data.startswith('Enviado:') : # Italian, English, French, Spanish
        context = 'Sent'
    return context


# extract from email address
def ExtractFrom(data):
    c = data.find('&#64;')
    a = data.rfind('>', 1, c) + 1
    b = data.find('<', c)
    frm = data[a:b]
    frm = frm.replace('&#64;', '@')
    return frm


# extract to email address
def ExtractTo(data):
    to = data.replace('&#64;', '@')
    return to


# decoding mail sent
def live_sent(msgfile, out_file):
    msg = {} # message
    mto = [] # emails address for to
    mfrom = [] # emails address for from
    mcc = [] # emails address for cc
    mbcc = [] # emails address for bcc
    parts = [] # parts
    sdate = "" # sent date
    rmid = "" # message ID
    subject = "" # subject
    
    # read file
    fp = open(msgfile)
    lines = fp.readlines()
    fp.close()
    limit = lines[0]
    limit = limit[:-2]
    new = empty = rec = False
    prt = {}  # single message part
    for line in lines:
        if empty == True:
            empty = False
            continue
        
        if new == True:
            # new time item
            if line.find('fRfc822MessageId') != -1:
                rec = 'Mid'
            elif line.find('fFrom') != -1:
                rec = 'From'
            elif line.find('fTo') != -1:
                rec = 'To'
            elif line.find('fCc') != -1:
                rec = 'Cc'
            elif line.find('fBcc') != -1:
                rec = 'Bcc'
            elif line.find('fSubject') != -1:
                rec = 'Subject'
            elif line.find('fMessageBody') != -1:
                rec = 'Body'
                prt['txt'] = ""
                prt['html'] = ""
                prt['filename'] = ""
                
            new = False
            empty = True
            continue
        
        if line.find(limit) != -1:
            if rec == 'Body':
                parts.append(prt)
            rec = None
            new = True
            
        if rec != None:
            if rec == 'Mid':
                rmid = line[:-1]
                rec = None
            elif rec == 'From':
                mfrom.append(line[:-1])
                rec = None
            elif rec == 'To':
                to = line[:-1]
                to = to.replace('""', '')
                to = to.replace(';', '')
                mto.append(to)
                rec = None
            elif rec == 'Cc':
                if (len(line[:-1]) > 1):
                    mcc.append(line[:-1])
                rec = None
            elif rec == 'Bcc':
                if (len(line[:-1]) > 1):
                    mbcc.append(line[:-1])
                rec = None
            elif rec == 'Subject':
                subject = line[:-1]
                rec = None
            elif rec == 'Body':
                prt['html'] += line
                
    ## compose message
    # to string
    tos = ""
    for elem in mto:
        if tos != "":
            tos += ","
        tos = tos + elem
    msg['to'] = tos
    
    # from string
    froms = ""
    for elem in mfrom:
        if froms != "":
            froms += ";"
        froms = froms + elem
    msg['from'] = froms
    
    # cc string
    ccs = ""
    for elem in mcc:
        if ccs != "":
            ccs += ","
        ccs = ccs + elem
    for elem in mbcc:
        if ccs != "":
            ccs += ","
        ccs = ccs + elem
    msg['cc'] = ccs
    
    # parts
    msg['parts'] = parts
    # info
    msg['messageid'] = rmid
    msg['subject'] = subject
    msg['received'] = ""
    msg['sent'] = sdate
    # new output file
    msg_out_file = out_file + '_0'
    save_msg(msg, msg_out_file)


def parse_rec_message(message):
    msg = {} # message
    mto = [] # emails address for to
    mfrom = [] # emails address for from
    mcc = [] # emails address for cc
    mbcc = [] # emails address for bcc
    parts = [] # parts
    rdate = "" # receive date
    sdate = "" # sent date
    
    # remove \r\n
    message = message.replace('\\r\\n', '\r\n')
    message = message.replace('\\"', '"')
    
    # message ID
    rmid_a = message.find('ReadMessageId')
    if rmid_a != -1:
        tmp = message[rmid_a:]
        rmid_a = tmp.find(';') + 1
        tmp = tmp[rmid_a:]
        rmid_b = tmp.find('&')
        rmid = tmp[:rmid_b]
    else:
        rmid = ""

    # find subject
    sbj_start = message.find('ReadMsgSubject')
    if sbj_start != -1:
        sbj_start = message.find('>', sbj_start) + 1
        sbj_end =  message.find('</', sbj_start)
        subject = message[sbj_start:sbj_end]
    else:
        subject = ""
        
    #extract to, from, cc, date
    tmp = message
    i = 0
    context = None
    while True:
        td = data_tag(tmp, 'td')
        if td != None:
            if context == None:
                context = LiveContext(td)
            else:
                if context == 'From':
                    mfrom.append(ExtractFrom(td))
                elif context == 'To':
                    mto.append(ExtractTo(td))
                elif context == 'Sent':
                    sdate = td
                context = None
            tmp = next_tag(message, 'td', i)
            i += 1
        else:
            break
        
    # find body and part/attatch
    prt = {}
    body = message.find('readMsgBodyContainer')
    if body != -1:
        body = message.find('<div', body)
        end = message.find('<iframe')
        #end = message.find('downloadFrame')
        html_body = '<div>' + message[body:end]
    else:
        html_body = ""
    prt['txt'] = ""
    prt['html'] = html_body
    prt['filename'] = ""
    parts.append(prt)

    ## compose message
    # to string
    tos = ""
    for elem in mto:
        if tos != "":
            tos += ","
        tos = tos + elem
    msg['to'] = tos
    
    # from string
    froms = ""
    for elem in mfrom:
        if froms != "":
            froms += ";"
        froms = froms + elem
    msg['from'] = froms
    
    # cc string
    ccs = ""
    for elem in mcc:
        if ccs != "":
            ccs += ","
        ccs = ccs + elem
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
def live_received(msgfile, out_file):
    # read file
    fp = open(msgfile)
    eformat = fp.read()
    fp.close()
    tmp = eformat
    
    # find extract main data
    msg = parse_rec_message(tmp)
    # new output file
    msg_out_file = out_file + '_0'
    save_msg(msg, msg_out_file)

    
def live_main(argv):
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
            live_sent(args[0], args[1])
            sys.exit(0)
        
    # received
    if len(args) != 2:
        usage(sys.argv)
        sys.exit(2)
    
    live_received(args[0], args[1])
    

if __name__ == '__main__':
    live_main(sys.argv[1:])
