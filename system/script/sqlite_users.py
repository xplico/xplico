#! /usr/bin/env python3
#
# Copyright (c) 2011 Gianluca Costa.  All Rights Reserved.
#
# Author: Gianluca Costa, 2012
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
import getopt
import sqlite3
import hashlib

ver = "1.0"
install_path = "/opt/xplico/"

# copyright and license
def xcopyright(argv):
    if argv[0][0:2] == './':
        name = argv[0][2:]
    else :
        name = argv[0]
    
    print(name+" version "+ver+"""
Copyright (c) 2012 Gianluca Costa. GNU GPL.
email: xplico@capanalysis.net
""")

# usage manual
def usage(argv):
    if argv[0][0:2] == './':
        name = argv[0][2:]
    else :
        name = argv[0]
    
    print("""Usage: """+name+""" -u <user_name> -p <user_password>""")

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:p:")
    except getopt.GetoptError:
        usage(sys.argv)
        sys.exit(2)
    passw = False
    uname = False
    username = ""
    password = ""
    # options
    for o, a in opts:
        # user
        if o == "-u":
            uname = True
            username = a
            
        # password
        if o == "-p":
            passw = True
            #password = md5.new(a).digest()
            password = hashlib.md5(a.encode('utf-8')).hexdigest()
        
    if not uname or not passw:
        xcopyright(sys.argv)
        usage(sys.argv)
        sys.exit(2)
    
    conn = sqlite3.connect(install_path+'/xplico.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, email, em_key, em_checked, first_name, last_name, group_id) VALUES (\""+username+"\", \"CapAnalysis.net\", \""+username+"@xxx.xx\", \"xxx\", 1, \""+username+"\",\""+username+"\", 2)")
    except:
        pass
    
    try:
        c.execute("UPDATE users SET password=\""+password+"\" WHERE username=\""+username+"\"")
        print("Ok")
    except:
        print("Error")
    conn.commit()
    c.close() 
        
    

