#!/usr/bin/env python3
#
# Copyright (c) 2012 Gianluca Costa & Andrea de Franceschi.
# Licensed under the following Creative Commons license: Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0).
# NOTE: If you need a written commercial license that's available
# on request from its author: xplico@iserm.com

# Author: Gianluca Costa, 2012
#      g.costa@xplico.org
#


import os

def main():
    olddb = '/opt/xplico/xplico.db'
    newdb = '/opt/xplico/xplico_new.db'
    schema_old = '/tmp/old.schema'
    schema_new = '/tmp/new.schema'

    # schemas files
    cmd = 'sqlite3 '+olddb+' .schema > '+schema_old
    os.system(cmd)
    cmd = 'sqlite3 '+newdb+' .schema > '+schema_new
    os.system(cmd)
    # compare
    oldfile = open(schema_old, "r").readlines()
    newfile = open(schema_new, "r").readlines()
    compare = False
    table_name = ''
    alter = []
    for nline in newfile:
        cok = False
        if nline.find('CREATE') != -1:
            table_name = nline.split()[2]
        else:
            np = nline.split()[0]
            for oline in oldfile:
                if oline.find('CREATE') != -1:
                    compare = False
                    if oline.find(table_name) != -1:
                        compare = True
                elif compare == True:
                    oline.replace(');', '')
                    soline = oline.split(',')
                    for so in soline:
                        try:
                            op = so.split()[0]
                            if np == op:
                                cok = True
                                break
                        except:
                            pass
                    if cok == True:
                        break
            if cok == False:
                if nline.find(');') == 0:
                    continue
                np = nline.split()[0]
                nt = nline.split()[1].replace(',', '')
                nt = nt.replace('(', '')
                alter.append('ALTER TABLE '+table_name+' ADD COLUMN '+np+' '+nt+';')
                
    if len(alter) != 0:
        for sql in alter:
            cmd = 'sqlite3 '+olddb+' "'+sql+'"'
            os.system(cmd)

if __name__ == '__main__':
    main()
