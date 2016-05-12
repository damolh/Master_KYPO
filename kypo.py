import paramiko
import getopt
import sys
import select
import json
import requests

# testing subject class
class TestingSubject:
    test_subject_count = 0

    def __init__(self, website_url, tunneling_method, pivot_server, pivot_username, web_server):
        self.website_url = website_url
        self.tunneling_method = tunneling_method
        self.pivot_server = pivot_server
        self.pivot_username = pivot_username
        self.web_server = web_server
        TestingSubject.test_subject_count += 1

    @staticmethod
    def display_count():
        print "Total number of testing subjects: %d" % TestingSubject.test_subject_count

    def display_details(self):
        print "Website url: ", self.website_url
        print "Tunneling method: ", self.tunneling_method
        print "Pivot server: ", self.pivot_server
        print "Pivot user: ", self.pivot_username
        print "Web server: ", self.web_server


# Arachni host class
class ArachniHost:
    arachni_host_count = 0

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        ArachniHost.arachni_host_count += 1

    @staticmethod
    def display_count():
        print "Total number of Arachni hosts: %d" % ArachniHost.arachni_host_count

    def display_details(self):
        print "Hostname: ", self.hostname
        print "Username: ", self.username


# method which prints instructions
def help():
    print "Usage: penetration_test.py   -n <NUMBER> -h <SANDBOX_NAME>"
    print "  -n                         specify the number of websites for penetration test"
    print "  -s                         specify the sandbox name"
    print "  -h                         output help information"	
    print "Examples: "
    print "penetration_test.py -n 1 -s sandbox_name"


# method which checks if the variable is int
def int_try_parse(value):
    try:
        int(value)
        return True
    except ValueError:
        return False


# method which creates a specified number of websites
def generate_websites(number_of_websites,websites):
    websites_counter = 0
    while websites_counter < int(number_of_websites):
        print "Data for website %s" % (websites_counter + 1)
        print "------------------"
        website_url = raw_input("Website url: ").strip('\n')
        tunneling_method = raw_input("Tunneling method: ").strip('\n')
        pivot_server = raw_input("Pivot server: ").strip('\n')
        pivot_username = raw_input("Pivot user: ").strip('\n')
        web_server = raw_input("Web server: ").strip('\n')
        test_subject = TestingSubject(website_url, tunneling_method, pivot_server, pivot_username, web_server)
        websites.append(test_subject)
        websites_counter += 1
    # remove the first empty object
    websites.remove(None)


# method which creates specified number of arachni hosts
def generate_arachni_hosts(websites, arachni_hosts):
    if len(websites) == 1:
        arachni_host_1 = ArachniHost('10.10.10.4', 'pentester', 'pentest')
        arachni_hosts.append(arachni_host_1)
    else:
        print "[x] Multiple Arachni hosts not supported [x]"
        sys.exit(1)
    # remove the first empty object
    arachni_hosts.remove(None)


# method which displays all the websites which should be tested
def display_websites(websites):
    if websites:
        TestingSubject.display_count()
        for website in websites:
            website.display_details()
    else:
        print "There are no websites to test!"


# method which displays all arachni hosts
def display_arachni_hosts(arachni_hosts):
    if arachni_hosts:
        ArachniHost.display_count()
        for arachni_host in arachni_hosts:
            arachni_host.display_details()
    else:
        print "There are no Arachni hosts!"


def main():

    if not len(sys.argv[1:]):
        help()
        sys.exit(1)

    # definition of basic variables
    smn_host = ''
    smn_username = ''
    smn_password = ''
    port = 22
    number_of_websites = ''
    websites = [None]
    arachni_hosts = [None]
	sandbox_name = ''

    # parse command line options
    try:
        options = getopt.getopt(sys.argv[1:],"n:h:s:", ["number_of_websites", "help_manual", "sandbox_name"])[0]
    except getopt.GetoptError as err:
        print str(err)
        help()
        sys.exit(1)

    # initialize arguments
    for option in options:
	    if option[0] in '-h':
		    help()
			sys.exit(1)
        elif option[0] in '-n':
            number_of_websites = option[1]
            if not int_try_parse(number_of_websites):
                print "Number cannot be parsed!"
                help()
                sys.exit(1)
            if (int(number_of_websites) < 1) or (int(number_of_websites) > 99):
                print "Incorrect number range! Insert number 1-99."
                help()
                sys.exit(1)
        elif option[0] in '-s':
		    sandbox_name = option[1]
		else:
            print "The option does not exist!"
            help()
            sys.exit(1)

    # generate websites and arachni hosts
    generate_websites(number_of_websites,websites)
    generate_arachni_hosts(websites, arachni_hosts)

    # clear terminal window
    sys.stderr.write("\x1b[2J\x1b[H")

    # print overview
    print "Overall information"
    print "-------------------"
    display_websites(websites)
    print '\n'
    display_arachni_hosts(arachni_hosts)
    print '\n'

    # establish connection
    print "[*] Trying to establish connection to " + smn_host + " [*]"
    establish_connection(smn_host, port, smn_username, smn_password, websites, arachni_hosts)


def establish_connection(smn_host, port, smn_username, smn_password, websites, arachni_hosts):

    # establish connection to KYPO (SMN)
    try:
        smn_client = paramiko.SSHClient()
        smn_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        smn_client.connect(smn_host,port=port,username=smn_username,password=smn_password)
        print "[*] Connection to " + smn_host + " established [*]"
    except paramiko.AuthenticationException:
        print "[x] Authentication failed when connecting to [x]" + smn_host
        sys.exit(1)

    # create bridge between SMN host and Arachni host
    transport = smn_client.get_transport()
    destination_addr = (arachni_hosts[0].hostname,port)
    local_addr = (smn_host, port)
    channel = transport.open_channel("direct-tcpip", destination_addr, local_addr)

    print "[*] Trying to establish connection to " + arachni_hosts[0].hostname + " [*]"

    # establish connection to Arachni host
    try:
        arachni_client = paramiko.SSHClient()
        arachni_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        arachni_client.connect(arachni_hosts[0].hostname, port=port, username=arachni_hosts[0].username, password=arachni_hosts[0].password, sock=channel)
        print "[*] Connection to " + arachni_hosts[0].hostname + " established [*]"
    except paramiko.AuthenticationException:
        print "[x] Authentication failed when connecting to " + arachni_hosts[0].hostname + " [x]"
        sys.exit(1)

    # prepare command to feed scanner
    arachni_command = ''

    if websites[0].tunneling_method == 'vpn':
        print "[x] Invalid tunneling method [x]"
        sys.exit(1)
    elif websites[0].tunneling_method == 'socks':
        print "[x] Invalid tunneling method [x]"
        sys.exit(1)
    elif websites[0].tunneling_method == 'ncat':
        arachni_command = 'Scanner/arachni-1.4-0.5.10/bin/arachni ' + websites[0].website_url + ' --http-proxy ' + websites[0].pivot_server+':8080'
    elif websites[0].tunneling_method == 'ssh':
        print "[x] Invalid tunneling method [x]"
        sys.exit(1)
    else:
        print "[x] Invalid tunneling method [x]"
        sys.exit(1)

    stdin, stdout, stderr = arachni_client.exec_command(arachni_command)

    while not stdout.channel.exit_status_ready():
        if stdout.channel.recv_ready():
            rl, wl, xl = select.select([stdout.channel], [], [], 0.0)
            if len(rl) > 0:
                print stdout.channel.recv(1024)

if __name__ == '__main__':
    main()