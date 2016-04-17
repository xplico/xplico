#! /usr/bin/env python3
#
# Copyright (c) 2012-16 Gianluca Costa.
#
# Author: Gianluca Costa
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
import zlib
import sqlite3
import hashlib
import time
import psycopg2

from httplib2 import Http

ver = "1.4"
install_path = "/opt/xplico/"

# copyright and license
def xcopyright(argv):
    if argv[0][0:2] == './':
        name = argv[0][2:]
    else :
        name = argv[0]
    
    print(name+" version "+ver+"""
Copyright (c) 2011-2016 Gianluca Costa & Andrea de Franceschi. GNU GPL.
""")


# usage manual
def usage(argv):
    if argv[0][0:2] == './':
        name = argv[0][2:]
    else :
        name = argv[0]
    
    print("""Usage: """+name+""" [-b 1|2] [-s] [-h] [-m <main_dir>] {-d <pol> <sol> | -a <pol> <session_name> | -n <case_name> <session_name> [<group_name>] | -r <pol> [<sol>] }
   <pol>: case ID
   <sol>: session ID
   <session_name>: session name
   <case_name>: case name
   <group_name>: group name (default: users)
   <main_dir>: main dir, by default /opt/xplico
   -d: create a dir tree on an existing case and session
   -a: create a new session with name <session_name> in the case with ID <pol> and add it in to DB
   -n: create a new case with name <case_name> and a new session with name <session_name> (inside this case) and update DB
   -h: this help
   -s: silent
   -m: change main dir repository
   -b: database: 1 for SQLite, 2 for PostgreSQL and 3 for MySQL
   -r: remove case with ID <pol> or remove session with ID <sol> inside the case <pol>
   
   For every protocol there is a subdirectory in the session  directory (/opt/xplico/pol_YY/sol_XX), you can add new directory for your modules, by editing the file /opt/xplico/cfg/sol_subdir.cfg, this give you the possibility to use Lucene-Solr even with your data.
""")


def Create(pol, sol):
    pol_path = install_path+"/pol_"+pol
    sess_path = install_path+"/pol_"+pol+"/sol_"+sol
    if not os.path.isdir(pol_path):
        os.mkdir(pol_path)
        os.chmod(pol_path, 0o777)
        os.mkdir(pol_path+'/tmp')
        os.chmod(pol_path+'/tmp', 0o777)
        os.mkdir(pol_path+'/log')
        os.chmod(pol_path+'/log', 0o777)
        os.mkdir(pol_path+'/cfg')
        os.chmod(pol_path+'/cfg', 0o777)
    if not os.path.isdir(sess_path):
        os.mkdir(sess_path)
        in_file = open(install_path+'/cfg/sol_subdir.cfg',"r")
        os.mkdir(sess_path+'/raw')
        os.chmod(sess_path+'/raw', 0o777)
        os.mkdir(sess_path+'/new')
        os.chmod(sess_path+'/new', 0o777)
        os.mkdir(sess_path+'/decode')
        os.chmod(sess_path+'/decode', 0o777)
        os.mkdir(sess_path+'/fault')
        os.chmod(sess_path+'/fault', 0o777)
        os.mkdir(sess_path+'/history')
        os.chmod(sess_path+'/history', 0o777)
        while True:
            in_line = in_file.readline()
            if in_line == '':
                break
            in_line = in_line[:-1]
            if in_line[0:1] == '#' or in_line == '':
                continue
            os.mkdir(sess_path+'/'+in_line)
            os.chmod(sess_path+'/'+in_line, 0o777)
        in_file.close()
    else: # upgrade dir tree
        in_file = open(install_path+'/cfg/sol_subdir.cfg',"r")
        while True:
            in_line = in_file.readline()
            if in_line == '':
                break
            in_line = in_line[:-1]
            if in_line[0:1] == '#' or in_line == '':
                continue
            if not os.path.isdir(sess_path+'/'+in_line):
                os.mkdir(sess_path+'/'+in_line)
                os.chmod(sess_path+'/'+in_line, 0o777)
        in_file.close()
        
        

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "sdlhanm:b:p:u:x:r")
    except getopt.GetoptError:
        usage(sys.argv)
        sys.exit(2)
    alim_a = alim_b = 2
    offset = 0
    lucene_update = False
    new_session = False
    new_case = False
    silent = False
    dissdir = False
    dbpassword = 123456
    dbuser = "xplico"
    dbname = "xplico"
    database = 1; # SQLite by default
    # options
    for o, a in opts:
        # dir
        if o == "-d":
            dissdir = True
        # silent
        if o == "-s":
            silent = True
        # help
        if o == "-h":
            usage(sys.argv)
        # lucene
        if o == "-l":
            lucene_update = True
        # new session
        if o == "-a":
            new_session = True
            if lucene_update:
                usage(sys.argv)
                sys.exit(2)
        # new case
        if o == "-n":
            new_case = True
            alim_b = 3
            if lucene_update or new_session:
                usage(sys.argv)
                sys.exit(2)
        # root dir
        if o == "-m":
            install_path = a
        # database
        if o == "-b":
            if a.isdigit():
                database = int(a)
            if database > 1:
                print("To use PostgreSQL contact: info@capanalysis.net")
                sys.exit(2)
        # password
        if o == "-p":
            dbpassword = a;
        # user
        if o == "-u":
            dbuser = a;
        # db name
        if o == "-x":
            dbname = a;
        # remove case or session
        if o == "-r":
            remove_case_session = True
            alim_b = 1
    
    if not silent:
        xcopyright(sys.argv)
    
    # check args
    if len(args) != alim_a+offset and len(args) != alim_b+offset:
        usage(sys.argv)
        sys.exit(2)
        
    if remove_case_session:
        if len(args) == 2: # remove session
            pol = args[offset]
            sol = args[offset+1]
            sess_path = install_path+"/pol_"+pol+"/sol_"+sol
            if os.path.isdir(sess_path):
                if database == 1: # SQLite
                    conn = sqlite3.connect(install_path+'/xplico.db')
                    c = conn.cursor()
                    c.execute("update sols set rm = 1 where id="+sol+";")
                    conn.commit()
                    c.close()
                if database == 2: # PostgreSQL
                    conn_string = "host='localhost' dbname='"+str(dbname)+"' user='"+str(dbuser)+"' password='"+str(dbpassword)+"'"
                    conn = psycopg2.connect(conn_string)
                    c = conn.cursor()
                    c.execute("update sols set rm = 1 where id="+sol+";")
                    conn.commit()
                    c.close()
                sess_rm = install_path+"/pol_"+pol+"/sol_rm"
                os.rename(sess_path, sess_rm)
                print("The session will be removed soon.")
            else:
                print("Session doesn't exist!")
        else: # remove case
            pol = args[offset]
            pol_path = install_path+"/pol_"+pol
            if os.path.isdir(pol_path):
                pol_rm = install_path+"/pol_"+pol+"/delete"
                open(pol_rm, 'a').close()
                print("The case will be removed soon.")
            else:
                print("Case doesn't exist!")
            
        sys.exit(2)
        
    if dissdir: # make dirs
        if not(args[offset].isdigit() and args[offset+1].isdigit()):
            print("Error:")
            if not args[offset].isdigit():
                print("  <pol> must be a digit")
            if not args[offset+1].isdigit():
                print("  <ses> must be a digit")
            sys.exit(2)
        pol = args[offset]
        sol = args[offset+1]
        Create(pol, sol)
        
    # new session
    if new_session:
        if database == 1: # SQLite
            pol = args[offset]
            sol_name = args[offset+1]
            if not pol.isdigit():
                print("Error:")
                print("  <pol> must be a digit")
                sys.exit(2)
            conn = sqlite3.connect(install_path+'/xplico.db')
            c = conn.cursor()
            c.execute("insert into sols (pol_id, name) values ("+pol+", \""+sol_name+"\")")
            sol = str(c.lastrowid)
            conn.commit()
            c.close()
            Create(pol, sol)
            if not silent:
                print("Put the pcap files here: "+install_path+"/pol_"+pol+"/sol_"+sol+"/new\n")
        
        if database == 2: # PostgreSQL
            pol = args[offset]
            sol_name = args[offset+1]
            if not pol.isdigit():
                print("Error:")
                print("  <pol> must be a digit")
                sys.exit(2)
            conn_string = "host='localhost' dbname='"+str(dbname)+"' user='"+str(dbuser)+"' password='"+str(dbpassword)+"'"
            conn = psycopg2.connect(conn_string)
            c = conn.cursor()
            c.execute("INSERT INTO sols (pol_id, name) VALUES ("+pol+", '"+sol_name+"')  RETURNING id")
            sol = str(c.fetchone()[0])
            conn.commit()
            c.close()
            Create(pol, sol)
            if not silent:
                print("Put the pcap files here: "+install_path+"/pol_"+pol+"/sol_"+sol+"/new\n")
            
    #new case
    if new_case:
        ntry = 5;
        if database == 1: # SQLite
            pol_name = args[offset]
            sol_name = args[offset+1]
            if (len(args) != alim_b+offset):
                grp_name = 'users'
            else:
                grp_name = args[offset+2]
            # search group name
            conn = sqlite3.connect(install_path+'/xplico.db')
            c = conn.cursor()
            while True:
                try:
                    c.execute("select id from groups where name=\""+grp_name+"\"")
                    break
                except:
                    time.sleep(1)
            gpr_exist = False
            for row in c:
                gpr_exist = True
                gpr_id = str(row[0])
                break
            if not gpr_exist:
                print('Error:')
                print(" The '"+grp_name+"' group don't exist!")
                sys.exit(2)
            # new case
            while True:
                try:
                    c.execute("insert into pols (group_id, name) values ("+gpr_id+", \""+pol_name+"\")")
                    break
                except:
                    print("There are problems with the SQLite: I can't insert the new case");
                    time.sleep(1)
                    ntry -= 1
                    if (ntry == 0):
                        break
            pol = str(c.lastrowid)
            # new session
            while True:
                try:
                    c.execute("insert into sols (pol_id, name) values ("+pol+", \""+sol_name+"\")")
                    break
                except:
                    print("There are problems with the SQLite: I can't insert the new session");
                    time.sleep(1)
                    ntry -= 1
                    if (ntry == 0):
                        break
            sol = str(c.lastrowid)
            conn.commit()
            c.close()
            Create(pol, sol)
            if not silent:
                print("Case ID: "+pol)
                print("Put the pcap files here: "+install_path+"/pol_"+pol+"/sol_"+sol+"/new\n")

        if database == 2: # PostgreSQL
            pol_name = args[offset]
            sol_name = args[offset+1]
            if (len(args) != alim_b+offset):
                grp_name = 'users'
            else:
                grp_name = args[offset+2]
            # search group name
            conn_string = "host='localhost' dbname='"+str(dbname)+"' user='"+str(dbuser)+"' password='"+str(dbpassword)+"'"
            conn = psycopg2.connect(conn_string)
            c = conn.cursor()
            while True:
                try:
                    c.execute("SELECT id FROM groups WHERE name = '"+grp_name+"'")
                    break
                except:
                    time.sleep(1)
            gpr_exist = False
            for row in c:
                gpr_exist = True
                gpr_id = str(row[0])
                break
            if not gpr_exist:
                print('Error:')
                print(" The '"+grp_name+"' group don't exist!")
                sys.exit(2)
            # new case
            while True:
                try:
                    c.execute("INSERT INTO pols (group_id, name) VALUES ("+gpr_id+", '"+pol_name+"') RETURNING id")
                    break
                except:
                    print("There are problems with the PostgreSQL server: I can't insert the new case");
                    time.sleep(1)
                    ntry -= 1
                    if (ntry == 0):
                        break
            pol = str(c.fetchone()[0])
            # new session
            while True:
                try:
                    c.execute("INSERT INTO sols (pol_id, name) VALUES ("+pol+", '"+sol_name+"') RETURNING id")
                    break
                except:
                    print("There are problems with the PostgreSQL server: I can't insert the new session");
                    time.sleep(1)
                    ntry -= 1
                    if (ntry == 0):
                        break
            sol = str(c.fetchone()[0])
            conn.commit()
            c.close()
            Create(pol, sol)
            if not silent:
                print("Case ID: "+pol)
                print("Put the pcap files here: "+install_path+"/pol_"+pol+"/sol_"+sol+"/new\n")
                
