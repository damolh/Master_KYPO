import paramiko
import getopt
import sys
import select
import json
import requests
import psycopg2
from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import random

# SQL Alchemy mapping
Base = declarative_base()
engine = create_engine('',echo=False)
metadata = MetaData(bind=engine)
session = sessionmaker()
session.configure(bind=engine)
s = session()


# testing subject class
class TestingSubject(Base):
    __table__ = Table('testing_subject', metadata, autoload=True, schema="pentest")

    def __init__(self, website_url, webserver_hostname, pivot_server, arachni_host, tunneling_method):
        self.website_url = website_url
        self.tunnel_method = tunneling_method
        self.pivot_server = pivot_server
        self.arachni_host = arachni_host
        self.webserver_hostname = webserver_hostname

    def display_details(self):
        print "Website url: ", self.website_url
        print "Tunneling method: ", self.tunnel_method
        print "Pivot server: ", self.pivot_server
        print "Arachni host: ", self.arachni_host
        print "Web server: ", self.webserver_hostname


# TestingSubject manager class
class TestingSubjectManager:
    def __init__(self, s):
        self.s = s

    def create_testing_subject(self, testing_subject):
        self.s.add(testing_subject)
        self.s.commit()


# Sandbox class
class Sandbox(Base):
    __table__ = Table('sandbox', metadata, autoload=True, schema="pentest")

    def __init__(self, name):
        self.name = name

    def display_details(self):
        print "Name: ", self.name


# Sandbox manager class
class SandboxManager:
    def __init__(self, s):
        self.s = s

    def create_sandbox(self, sandbox):
        rest_url = "http://kypo.ics.muni.cz:5000/scenario/sandbox/load/" + sandbox.name + "/konicek-vizvary.json"
        response = requests.get(rest_url)
        if response.ok:
            jData = json.loads(response.content)
            print jData

            self.s.add(sandbox)
            self.s.commit()
        else:
            response.raise_for_status()
            sys.exit(1)

    def delete_sandbox(self, sandbox):
        rest_url = "http://kypo.ics.muni.cz:5000/scenario/sandbox/delete/" + sandbox.name
        response = requests.get(rest_url)
        if response.ok:
            jData = json.loads(response.content)
            print jData

            sandbox = self.s.query(Sandbox).filter_by(name=sandbox.name).first()
            self.s.delete(sandbox)
            self.s.commit()

    def get_sandbox_byname(self, sandbox_name):
        sandbox = self.s.query(Sandbox).filter_by(name=sandbox_name).first()
        return sandbox


# Pentester class
class Pentester(Base):
    __table__ = Table('pentest_user', metadata, autoload=True, schema="pentest")

    def __init__(self, email):
        self.email = email


# Pentester manager class
class PentesterManager:
    def __init__(self, s):
        self.s = s

    def create_pentester(self, pentester):
        s.add(pentester)
        s.commit()

    def get_pentester_byemail(self, pentester_email):
        pentester = self.s.query(Pentester).filter_by(email=pentester_email).first()
        return pentester


# Arachni host class
class ArachniHost(Base):
    __table__ = Table('arachni_host', metadata, autoload=True, schema="pentest")

    def __init__(self, hostname, username, password, name):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.name = name

    def display_details(self):
        print "Hostname: ", self.hostname
        print "Username: ", self.username


# ArachniHost manager class
class ArachniHostManager:
    def __init__(self, s):
        self.s = s

    def create_arachni_host(self, arachni_host, sandbox_name):
        if arachni_host.hostname == "10.10.10.4":
            s.add(arachni_host)
            s.commit()
        else:
            rest_url = "http://kypo.ics.muni.cz:5000/scenario/" + sandbox_name + "/host/copy/arachni/" + arachni_host.name + "/" + arachni_host.hostname
            response = requests.get(rest_url)
            if response.ok:
                jData = json.loads(response.content)
                print jData

                self.s.add(arachni_host)
                self.s.commit()
            else:
                response.raise_for_status()
                sys.exit(1)

    def get_arachni_host_byhostname(self, hostname):
        arachni_host = self.s.query(ArachniHost).filter_by(hostname=hostname).first()
        return arachni_host


# Pivot class
class PivotServer(Base):
    __table__ = Table('pivot_server', metadata, autoload=True, schema="pentest")

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password

    def display_details(self):
        print "Hostname: ", self.hostname
        print "Username: ", self.username


# PivotServer manager class
class PivotServerManager:
    def __init__(self, s):
        self.s = s

    def create_pivot_server(self, pivot_server):
        s.add(pivot_server)
        s.commit()


# method which prints instructions
def help():
    print "Usage: penetration_test.py   -n <NUMBER> -s <SANDBOX_NAME> -u <USER_EMAIL>"
    print "  -n                         specify the number of websites for penetration test"
    print "  -s                         specify the sandbox name"
    print "  -u                         specify the user email"
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
def generate_websites(number_of_websites):
    websites_counter = 0
    pivot_server_manager = PivotServerManager(s)
    testing_subject_manager = TestingSubjectManager(s)
    while websites_counter < int(number_of_websites):
        print "Data for website %s" % (websites_counter + 1)
        print "------------------"
        website_url = raw_input("Website url: ").strip('\n')
        tunneling_method = raw_input("Tunneling method: ").strip('\n')
        pivot_server = raw_input("Pivot server: ").strip('\n')
        pivot_username = raw_input("Pivot user: ").strip('\n')
        web_server = raw_input("Web server: ").strip('\n')
        pivot_complete = PivotServer(pivot_server,pivot_username,None)
        pivot_server_manager.create_pivot_server(pivot_complete)
        testing_subject = TestingSubject(website_url,web_server,pivot_complete.id,None, tunneling_method)
        testing_subject_manager.create_testing_subject(testing_subject)

        websites_counter += 1
    # remove the first empty object


# method which creates a specified number of arachni hosts
def generate_arachni_hosts(number_of_hosts, sandbox_name):
    network_prefix = "10.10.10."
    hosts = number_of_hosts
    arachni_hosts = [None]
    arachni_host_manager = ArachniHostManager(s)
    default_arachni_host = arachni_host_manager.get_arachni_host_byhostname("10.10.10.4")

    if (not default_arachni_host) and (int(number_of_hosts) == 1):
        default_arachni_host = ArachniHost('10.10.10.4', 'pentester', 'pentest', 'arachni')
        arachni_host_manager.create_arachni_host(default_arachni_host,sandbox_name)
        arachni_hosts.append(default_arachni_host)
        arachni_hosts.remove(None)
        return arachni_hosts
    elif (not default_arachni_host) and (int(number_of_hosts) > 1):
        default_arachni_host = ArachniHost('10.10.10.4', 'pentester', 'pentest', 'arachni')
        arachni_host_manager.create_arachni_host(default_arachni_host, sandbox_name)
        arachni_hosts.append(default_arachni_host)
        hostname = ''


        for x in range(0, (int(number_of_hosts)-1)):
            arachni_exitst = True
            while(arachni_exitst):
                host_ip = random.SystemRandom().randint(0,255)

                hostname = "10.10.10.%d" % host_ip
                test_arachni = arachni_host_manager.get_arachni_host_byhostname(hostname)
                if not test_arachni:
                    arachni_exitst = False
            name = default_arachni_host.name + "%d" % host_ip

            arachni_host = ArachniHost(hostname, default_arachni_host.username, default_arachni_host.password, name)
            arachni_host_manager.create_arachni_host(arachni_host, sandbox_name)
            arachni_hosts.append(arachni_host)
    else:
        for x in range(0, int(number_of_hosts)):
            print "ble %d" % (x)
            arachni_exitst = True
            while (arachni_exitst):
                host_ip = random.SystemRandom().randint(0, 255)

                hostname = "10.10.10.%d" % host_ip
                test_arachni = arachni_host_manager.get_arachni_host_byhostname(hostname)
                if not test_arachni:
                    arachni_exitst = False
            name = default_arachni_host.name + "%d" % host_ip


            arachni_host = ArachniHost(hostname, default_arachni_host.username, default_arachni_host.password, name)
            arachni_host_manager.create_arachni_host(arachni_host, sandbox_name)
            arachni_hosts.append(arachni_host)

    arachni_hosts.remove(None)
    return arachni_hosts


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

        for arachni_host in arachni_hosts:
            arachni_host.display_details()
    else:
        print "There are no Arachni hosts!"


def main():

    if len(sys.argv[1:]) < 1:
        help()
        sys.exit(1)

    # definition of basic variables
    smn_host = ''
    smn_username = ''
    smn_password = ''
    port = 22
    number_of_websites = ''
    websites = [None]

    sandbox_name = ''
    user_email = ''

    # parse command line options
    try:
        options = getopt.getopt(sys.argv[1:],"n:h:s:u:", ["number_of_websites", "help_manual", "sandbox_name", "user_email"])[0]
    except getopt.GetoptError as err:
        print str(err)
        help()
        sys.exit(1)

    # initialize arguments
    for option in options:
        if option[0] in '-h':
            help()
            sys.exit(1)
        elif option[0] in '-u':
            user_email = option[1]
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



    # check if user already exists if not create a new user
    pentester_manager = PentesterManager(s)
    pentester = pentester_manager.get_pentester_byemail(user_email)

    if not pentester:
        pentester = Pentester(user_email)
        pentester_manager.create_pentester(pentester)

    # check if sandbox already exists if not create a new sandbox
    sandbox_manager = SandboxManager(s)
    sandbox = sandbox_manager.get_sandbox_byname(sandbox_name)

    if not sandbox:
        sandbox = Sandbox(sandbox_name)
        sandbox_manager.create_sandbox(sandbox)

    # generate websites and arachni hosts
    generate_websites(number_of_websites)
    arachni_hosts = generate_arachni_hosts(number_of_websites, sandbox_name)

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
    #establish_connection(smn_host, port, smn_username, smn_password, websites, arachni_hosts)


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