#!/usr/bin/env python

import sys, hashlib
PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL + "./")

from androguard.core.androgen import AndroguardS
from androguard.core.analysis import analysis

TEST = "../../../apk/FakeLocation_2.94.apk"
# TEST = "../../apk/iCalendar_malware.apk"

def display_CFG(a, x, classes):
    for method in a.get_methods():
        g = x.get_method( method )

        print method.get_class_name(), method.get_name(), method.get_descriptor()
        for i in g.basic_blocks.get():
            print "\t %s %x %x" % (i.name, i.start, i.end), '[ NEXT = ', ', '.join( "%x-%x-%s" % (j[0], j[1], j[2].get_name()) for j in i.childs ), ']', '[ PREV = ', ', '.join( j[2].get_name() for j in i.fathers ), ']'


def display_PERMISSION(a, x, classes):
    # Show methods used by permission
    perms_access = x.get_tainted_packages().get_permissions( [] )
    for perm in perms_access:
        print "PERM : ", perm
        analysis.show_Paths( a, perms_access[ perm ] )

a = AndroguardS( TEST )
x = analysis.uVMAnalysis( a.get_vm() )
classes = a.get_vm().get_classes_names()
vm = a.get_vm()

display_CFG( a, x, classes )
# display_PERMISSION( vm, x, classes )