__author__ = 'whewawal'
#!/usr/bin/env python

#requires all cimc ip adrresses to be in a file ex .cimc.txt(Note: require IPs not hostnames)
#writes (apends) log to log.out in the current directory
#writes mac info in to patch_file in current directory ex patch.txt
#requires hostnames to be in DNS for reverse name resolution
#example run options
#python check_ucs_conns.py -c cimc.txt -u1 <cimc user> -p1 <cimc password> -u2 <switch user> -p2 <switch password> -ip1 <switch1 ip> -ip2 <switch2 ip> -o patch.txt -l log.txt -v 1

import pexpect
import argparse
import subprocess
import re

if __name__ == '__main__':


    parser = argparse.ArgumentParser(description='CLI arg parser')
    parser.add_argument('-c', '--cimc', help='CIMC IP address file name', required=True)
    parser.add_argument('-u1', '--username1', help='Username to log into the CIMC.', required=True)
    parser.add_argument('-u2', '--username2', help='Username to log into the Leaf.', required=True)
    parser.add_argument('-p1', '--passwd1', help='Password to log in to CIMC.', required=True)
    parser.add_argument('-p2', '--passwd2', help='Password to log in to Leaf.', required=True)
    parser.add_argument('-o', '--patch', help='patch details file name to be created', required=True)
    parser.add_argument('-ip1', '--ip1', help='ip of leaf switch 1', required=True)
    parser.add_argument('-ip2', '--ip2', help='ip of leaf switch 2', required=True)
    parser.add_argument('-l', '--log', help='Log file name', required=True)
    parser.add_argument('-v', '--verbose', help='Verbose to see all CIMC and leaf output on stdout', required=True)
    args = parser.parse_args()



    cimc_address_list = []
    cimc_user_name = args.username1
    cimc_passwd = args.passwd1
    verbose = True
    cimc_address_file = open(args.cimc, 'r')
    cimc_log_file = open(args.log, 'w')
    patch_file = open(args.patch, 'w')
    x = 0
    j = ""
    leaf1_ip = args.ip1
    leaf2_ip = args.ip2
    user_name = args.username2
    passwd = args.passwd2
    x = 1
    y = 1

    #Read leaf 1 lldp neighbors in to a list

    try:
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no %s@%s' %(user_name, leaf1_ip))
        #child.logfile = sys.stdout
        child.logfile = cimc_log_file
        child.timeout = 20
        child.expect('Password:', timeout=120)
        child.sendline(passwd)
        child.expect('#')
    except pexpect.TIMEOUT:
        print "SSH Timeout"

    print "Successfully Logged in to the Leaf1"
    child.sendline('term len 0')
    child.expect('#')
    child.sendline('show lldp neighbors')
    child.expect('#')
    items1 = child.before.split()

    #Read leaf 2 lldp neighbors in to a list

    try:
        child = pexpect.spawn('ssh -o StrictHostKeyChecking=no %s@%s' %(user_name, leaf2_ip))
        #child.logfile = sys.stdout
        child.logfile = cimc_log_file
        child.timeout = 20
        child.expect('Password:', timeout=120)
        child.sendline(passwd)
        child.expect('#')
    except pexpect.TIMEOUT:
        print "SSH Timeout"

    print "Successfully Logged in to the Leaf2"
    child.sendline('term len 0')
    child.expect('#')
    child.sendline('show lldp neighbors')
    child.expect('#')
    items2 = child.before.split()

    #CIMC detail gathering
    host_look_up =""
    server_name = []

    for i in cimc_address_file:
        cimc_address_list.append(i)
    for j in cimc_address_list:
        #call("host " + j, shell=True)
        found_mlom1_leaf1 = False
        found_mlom1_leaf2 = False
        found_mlom2_leaf1 = False
        found_mlom2_leaf2 = False

        found_e2_leaf1 = False
        found_e2_leaf2 = False
        found_e3_leaf1 = False
        found_e3_leaf2 = False

        host_look_up = "host "+j
        proc = subprocess.Popen(host_look_up, stdout=subprocess.PIPE, shell=True)
        server_name = proc.communicate()[0].split()


        print "Logging in to %s" %server_name[4]
        patch_file.write(server_name[4])
        patch_file.write("\n")

        try:
            child = pexpect.spawn('ssh -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 %s@%s' %(cimc_user_name, j))
            if verbose:
                #child.logfile = sys.stdout
                child.logfile = cimc_log_file
                child.timeout = 20
                #child.expect('login as:')
                child.expect('password:', timeout=120)

            #index=child.expect(['(yes/no)','Password:'])
            #if index == 0:
            #    child.sendline("yes")
            #    child.expect('Password:')

            child.sendline(cimc_passwd)
            child.expect('#')
        except pexpect.TIMEOUT:
            print "SSH Timeout"


        print "Successfully Logged in to the CIMC"
        child.sendline('scope chassis')
        child.expect('#')
        child.sendline('show adapter | grep MLOM')
        child.expect('#')
        items = child.before.split()

        print "Getting MAC Address details for MLOM NICS"
        child.sendline('connect debug-shell %s' %items[5])
        child.expect('#')
        child.timeout = 10
        child.sendline('attach-mcp')
        child.expect('#')
        child.sendline('dcem-port 0')
        child.expect('#')
        dcem0 = child.before.split()

        child.sendline('dcem-port 1')
        child.expect('#')
        dcem1 = child.before.split()

        print "MAC for MLOM1 is %s" %dcem0[8]
        print "MAC for MLOM2 is %s" %dcem1[8]

        for k in items1:
            x = x + 1
            if k.replace(".", "") == dcem0[8].replace(":", ""):
                found_mlom1_leaf1 = True
                print "E0 with MAC %s is connected to %s on leaf 1" %(dcem0[8], items1[x-4])
                patch_file.write("E0 with MAC ")
                patch_file.write(dcem0[8])
                patch_file.write(" is connected to leaf 1 ")
                patch_file.write(items1[x-4])
                patch_file.write("\n")


        for l in items2:
            y = y + 1
            if l.replace(".", "") == dcem0[8].replace(":", ""):
                found_mlom1_leaf2 = True
                print "E0 with MAC %s is connected to %s on leaf 2" %(dcem0[8], items2[y-4])
                patch_file.write("E0 with MAC ")
                patch_file.write(dcem0[8])
                patch_file.write(" is connected to leaf 2 ")
                patch_file.write(items2[y-4])
                patch_file.write("\n")


        x = 1
        y = 1

        for m in items1:
            x = x + 1
            if m.replace(".", "") == dcem1[8].replace(":", ""):
                found_mlom2_leaf1 = True
                print "E1 with MAC %s is connected to %s on leaf 1" %(dcem1[8], items1[x-4])
                patch_file.write("E1 with MAC ")
                patch_file.write(dcem1[8])
                patch_file.write(" is connected to leaf 1 ")
                patch_file.write(items1[x-4])
                patch_file.write("\n")


        for n in items2:
            y = y + 1
            if n.replace(".", "") == dcem1[8].replace(":", ""):
                found_mlom2_leaf2 = True
                print "E1 with MAC %s is connected to %s on leaf 2" %(dcem1[8], items2[y-4])
                patch_file.write("E1 with MAC ")
                patch_file.write(dcem1[8])
                patch_file.write(" is connected to leaf 2 ")
                patch_file.write(items2[y-4])
                patch_file.write("\n")



        child.sendline('exit')
        child.expect('#')
        child.sendline('exit')
        child.expect('#')

        child.sendline('show adapter | grep PCIE')
        child.expect('#')
        pcie_present = re.search('PCIE', child.before.strip('show adapter | grep PCIE'))


        if pcie_present == None:
            print "No PCIE NIC present in this server"
            patch_file.write("No PCIE NIC present in this server")
            patch_file.write("\n")
        else:
            items_pcie = child.before.split()
            print "Getting MAC Address details for PCIE NICS"
            child.sendline('connect debug-shell %s' %items_pcie[5])
            child.expect('#')
            child.sendline('attach-mcp')
            child.expect('#')
            child.sendline('dcem-port 0')
            child.expect('#')
            dcem0_pcie = child.before.split()
            child.sendline('dcem-port 1')
            child.expect('#')
            dcem1_pcie = child.before.split()

            print "MAC for E2 is %s" %dcem0_pcie[8]
            print "MAC for E3 is %s" %dcem1_pcie[8]

            x = 1
            y = 1

            for k in items1:
                x = x + 1
                if k.replace(".", "") == dcem0_pcie[8].replace(":", ""):
                    found_e2_leaf1 = True
                    print "E2 with MAC %s is connected to %s on leaf 1 " %(dcem0_pcie[8], items1[x-4])
                    patch_file.write("E2 with MAC ")
                    patch_file.write(dcem0_pcie[8])
                    patch_file.write("is connected to leaf 1 ")
                    patch_file.write(items1[x-4])
                    patch_file.write("\n")

            for l in items2:
                y = y + 1
                if l.replace(".", "") == dcem0_pcie[8].replace(":", ""):
                    found_e2_leaf2 = True
                    print "E2 with MAC %s is connected to %s on leaf 2 " %(dcem0[8], items2[y-4])
                    patch_file.write("E2 with MAC ")
                    patch_file.write(dcem0_pcie[8])
                    patch_file.write("is connected to leaf 2 ")
                    patch_file.write(items2[y-4])
                    patch_file.write("\n")
            x = 1
            y = 1

            for m in items1:
                x = x + 1
                if m.replace(".", "") == dcem1_pcie[8].replace(":", ""):
                    found_e3_leaf1 = True
                    print "E3 with MAC %s is connected to %s on leaf 1 " %(dcem1_pcie[8], items1[x-4])
                    patch_file.write("E3 with MAC ")
                    patch_file.write(dcem1_pcie[8])
                    patch_file.write("is connected to leaf 1 ")
                    patch_file.write(items1[x-4])
                    patch_file.write("\n")

            for n in items2:
                y = y + 1
                if n.replace(".", "") == dcem1_pcie[8].replace(":", ""):
                    found_e3_leaf2 = True
                    print "E3 with MAC %s is connected to %s on leaf 2 " %(dcem1_pcie[8], items2[y-4])
                    patch_file.write("E3 with MAC ")
                    patch_file.write(dcem1_pcie[8])
                    patch_file.write("is connected to leaf 2 ")
                    patch_file.write(items2[y-4])
                    patch_file.write("\n")



        x = 1
        y = 1
        child.sendline('quit')


    patch_file.close()
    print "MAC Address details collected sucessfully"
