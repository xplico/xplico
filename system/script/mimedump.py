#!/usr/bin/env python3
#
# Copyright (c) 2011 Gianluca Costa & Andrea de Franceschi.
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


import os
import sys
import email
import errno
import mimetypes

from optparse import OptionParser
from email.header import decode_header


def main():
    parser = OptionParser(usage="""\
%prog [options] msgfile

Unpack a MIME message into a directory of files.
Copyright (c) 2007-2011 Gianluca Costa & Andrea de Franceschi. License GNU GPL.
""")
    parser.add_option('-d', '--directory',
                      type='string', action='store',
                      help="""Unpack the MIME message into the named
                      directory, which will be created if it doesn't already
                      exist.""")
    opts, args = parser.parse_args()
    try :
        msgfile = args[0]
    except IndexError:
        parser.print_help()
        sys.exit(1)
    msgfile_sc = ''
    fp = open(msgfile)
    try :
        msg = email.message_from_binary_file(fp)
    except :
        try :
            msg = email.message_from_file(fp)
        except :
            fp.close()
            fi = open(msgfile, 'rb')
            msgfile_sc = msgfile+'s'
            fo = open(msgfile_sc, 'w')
            for l in fi :
                u = l.decode("utf-8", 'ignore')
                fo.write(u)
            fi.close()
            fo.close()
            fp = open(msgfile_sc)
            msg = email.message_from_file(fp)
    fp.close()
    if msgfile_sc != '' :
        os.remove(msgfile_sc)
        
    print('SUBJECT:')
    try:
        lsnam = decode_header(msg['subject'])
        dec = ' '
        for el in lsnam :
            if el[1] == None :
                try:
                    dec = dec + el[0]
                except:
                    dec = dec + el[0].decode('utf-8')
            else :
                dec = dec + el[0].decode(el[1])
        print(dec)
    except:
        print('-(no sobject)-')
    
    print('FROM:')
    lsnam = decode_header(msg['from'])
    dec = ' '
    for el in lsnam :
        if el[1] == None :
            try:
                dec = dec + el[0]
            except:
                dec = dec + el[0].decode('utf-8')
        else :
            dec = dec + el[0].decode(el[1])
    print(dec)
    
    print('TO:')
    dec = ' '
    try:
        lsnam = decode_header(msg['to'])
        for el in lsnam :
            if el[1] == None :
                try:
                    dec = dec + el[0]
                except:
                    dec = dec + el[0].decode('utf-8')
            else :
                dec = dec + el[0].decode(el[1])
    except:
        pass
    print(dec)

    
    if msg['cc']:
        lsnam = decode_header(msg['cc'])
        dec = ' '
        for el in lsnam :
            if el[1] == None :
                try:
                    dec = dec + el[0]
                except:
                    dec = dec + el[0].decode('utf-8')
            else :
                dec = dec + el[0].decode(el[1])
        print(dec)
    
    if not opts.directory:
        sys.exit(1)
        
    try:
        os.mkdir(opts.directory)
    except OSError as e:
        # Ignore directory exists error
        if e.errno != errno.EEXIST:
            raise
        
    counter = 1
    for part in msg.walk():
        # multipart/* are just containers
        if part.get_content_maintype() == 'multipart':
            continue
        # Applications should really sanitize the given filename so that an
        # email message can't be used to overwrite important files
        filename = part.get_filename()
        if filename:
            filename = filename.replace('/', '');
            filename = 'part-%03d%s' % (counter, filename)
            print(filename)
            counter += 1
            fp = open(os.path.join(opts.directory, filename), 'wb')
            fp.write(part.get_payload(decode=True))
            fp.close()

if __name__ == '__main__':
    main()
