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
    Usage: """+name+""" [-h] [-s] <aol_web_mail> <output_file>
       <aol_web_mail>: web mail sent or received
       <output_file>: file in mwmail (manipulator) format
       -s : if set the email is sent, otherwise is received
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


# decoding mail sent
def aol_sent(msgfile, out_file):
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
    fp = open(msgfile, 'rb')
    message = fp.read().decode("utf-8", 'ignore')
    fp.close()
        
    # find subject
    sbj_start = message.find(',"Subject":"')
    if sbj_start != -1:
        sbj_start = sbj_start + 12
        sbj_end = message.find('","', sbj_start)
        subject = message[sbj_start:sbj_end]
    else:
        subject = ""
        
    #extract to, from, cc
    end = message.find('"RichBody":"')
    #extract to
    me = 0
    ms = message.find('","To":"', me, end)
    if ms != -1:
        ms += 8
        me = message.find('","', ms)
        me_2 = message.find(',","', ms)
        if me_2 != -1:
            if me_2 < me:
                me = me_2
        mto.append(message[ms:me])
    #extract from
    me = 0
    ms = message.find('"From":"', me, end)
    if ms != -1:
        ms += 8
        me = message.find('","', ms)
        mfrom.append(message[ms:me])
    #extract cc
    me = 0
    ms = message.find('","Cc":"', me, end)
    if ms != -1:
        ms += 8
        me = message.find('","', ms)
        me_2 = message.find(',","', ms)
        if me_2 != -1:
            if me_2 < me:
                me = me_2
        mcc.append(message[ms:me])
    #extract cc
    me = 0
    ms = message.find('","Bcc":"', me, end)
    if ms != -1:
        ms += 9
        me = message.find('","', ms)
        me_2 = message.find(',","', ms)
        if me_2 != -1:
            if me_2 < me:
                me = me_2
        mbcc.append(message[ms:me])

    # find body and part/attatch
    prt = {}
    body = message.find('","RichBody":"')
    if body != -1:
        body += 14
        body_end = message.find('","PlainBody":"', body)
        html_body = message[body:body_end]
        # replace \r\n
        html_body = html_body.replace('\\r\\n', '\r\n')
        html_body = html_body.replace('\\n', '\n')
    else:
        html_body = ""
    body = message.find('","PlainBody":"')
    if body != -1:
        body += 15
        body_end = message.find('","RichEdit":', body)
        txt_body = message[body:body_end]
        # replace \r\n
        txt_body = txt_body.replace('\\r\\n', '\r\n')
        txt_body = txt_body.replace('\\n', '\n')
    else:
        txt_body = ""
        
    prt['txt'] = txt_body
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
    
    # message ID
    rmid_a = message.find('"messageID":"')
    if rmid_a != -1:
        rmid_a = message.find('<', rmid_a)
        rmid_b = message.find('>', rmid_a) + 1
        rmid = message[rmid_a:rmid_b]
    else:
        rmid = ""
        
    # find subject
    sbj_start = message.find(',"subject":"')
    if sbj_start != -1:
        sbj_start = sbj_start + 12
        sbj_end = message.find('","', sbj_start)
        subject = message[sbj_start:sbj_end]
    else:
        subject = ""

    # sent time
    a = message.find('","sentTime":"')
    if a != -1:
        a += 14
        b =  message.find('","', a)
        sdate = message[a:b]

    # received time
    a = message.find('","receivedTime":')
    if a != -1:
        a += 17
        b = message.find(',"', a)
        #rdate = num2date(message[a:b])
        
    #extract to, from, cc
    ms = 0
    me = 0
    end = message.find('"body":"')
    #extract to
    while True:
        ms = message.find(',"to":[{"', me, end)
        if ms != -1:
            me =  message.find('"}],"', ms)
            mess_b = ms
            while True:
                mess_a = message.find('"displayForm":"', mess_b, me)
                if mess_a != -1:
                    mess_a += 15
                    mess_b = message.find('","', mess_a, me)
                    mto.append(message[mess_a:mess_b])
                else:
                    break
        else:
            break
        
    #extract from
    me = 0
    while True:
        ms = message.find(',"from":[{"', me)
        if ms != -1:
            me =  message.find('"}],"', ms)
            mess_b = ms
            while True:
                mess_a = message.find('"displayForm":"', mess_b, me)
                if mess_a != -1:
                    mess_a += 15
                    mess_b = message.find('","', mess_a, me)
                    mfrom.append(message[mess_a:mess_b])
                else:
                    break
        else:
            break
        
    #extract cc
    me = 0
    while True:
        ms = message.find('","cc":[{"', me)
        if ms != -1:
            me =  message.find('"}],"', ms)
            mess_b = ms
            while True:
                mess_a = message.find('"displayForm":"', mess_b, me)
                if mess_a != -1:
                    mess_a += 15
                    mess_b = message.find('","', mess_a, me)
                    mcc.append(message[mess_a:mess_b])
                else:
                    break
        else:
            break
    
    # find body and part/attatch
    prt = {}
    body = message.find(',"body":"')
    if body != -1:
        body += 9
        body_end = message.find('","inputFrom":"', body)
        html_body = message[body:body_end]
        # replace \r\n
        html_body = html_body.replace('\\r\\n', '\r\n')
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
def aol_received(msgfile, out_file):
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

    
def aol_main(argv):
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
            aol_sent(args[0], args[1])
            sys.exit(0)
        
    # received
    if len(args) != 2:
        usage(sys.argv)
        sys.exit(2)
    
    aol_received(args[0], args[1])
    

if __name__ == '__main__':
    aol_main(sys.argv[1:])
