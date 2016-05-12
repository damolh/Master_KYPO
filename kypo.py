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

# SQL Alchemy mapping
Base = declarative_base()
engine = create_engine('',echo=False)
metadata = MetaData(bind=engine)
session = sessionmaker()
session.configure(bind=engine)
s = session()

# testing subject class
class TestingSubject:
    test_subject_count = 0

    def __init__(self, website_url, tunneling_method, pivot_server, arachni_host, web_server):
        self.website_url = website_url
        self.tunneling_method = tunneling_method
        self.pivot_server = pivot_server
        self.arachni_host = arachni_host
        self.web_server = web_server
        TestingSubject.test_subject_count += 1

    @staticmethod
    def display_count():
        print "Total number of testing subjects: %d" % TestingSubject.test_subject_count

    def display_details(self):
        print "Website url: ", self.website_url
        print "Tunneling method: ", self.tunneling_method
        print "Pivot server: ", self.pivot_server
        print "Arachni host: ", self.arachni_host
        print "Web server: ", self.web_server


# TestingSubject manager class
class TestingSubjectManager:
    def __init__(self, db_connection):
        TestingSubjectManager.cursor = db_connection.cursor()
        self.db_connection = db_connection

    def create_testing_subject(self, testing_subject):
        TestingSubjectManager.cursor.execute(
            "INSERT INTO pentest.testing_subject (website_url,webserver_hostname,pivot_server,arachni_host,tunnel_method)"
            " VALUES (%s, %s, %s, s%, s%)",
            (testing_subject.website_url, testing_subject.webserver_hostname, testing_subject.pivot_server,
             testing_subject.arachni_host, testing_subject.tunneling_method,))
        self.db_connection.commit()
        TestingSubject.cursor.close()


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
        rest_url = "https://kypo.ics.muni.cz/proxy/kypo.ics.muni.cz/5000/scenario/sandbox/load/" + sandbox.name + "/konicek-vizvary.json"
        response = requests.get(rest_url)
        if response.ok:
            jData = json.loads(response.content)

            self.s.add(sandbox)
            self.s.commit()
        else:
            response.raise_for_status()
            sys.exit(1)

    def get_sandbox_byname(self, sandbox_name):
        sandbox = self.s.query(Sandbox).filter_by(name=sandbox_name).first()
        return sandbox

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


# ArachniHost manager class
class ArachniHostManager:
    def __init__(self, db_connection):
        ArachniHostManager.cursor = db_connection.cursor()
        self.db_connection = db_connection

    def create_arachni_host(self, arachni_host):
        ArachniHostManager.cursor.execute("INSERT INTO pentest.arachni_host (hostname,username,password) VALUES (%s, %s, %s)",
                                            (arachni_host.hostname,arachni_host.username,arachni_host.password,))
        self.db_connection.commit()
        ArachniHostManager.cursor.close()


# Pentester class
class Pentester:
    pentester_count = 0

    def __init__(self, pentester_email):
        self.pentester_email = pentester_email
        Pentester.pentester_count += 1


# Pentester manager class
class PentesterManager:
    def __init__(self, db_connection):
        PentesterManager.cursor = db_connection.cursor()
        self.db_connection = db_connection

    def create_pentester(self, pentester):
        PentesterManager.cursor.execute("INSERT INTO pentest.pentest_user (email) VALUES (%s)",
                                        (pentester.pentester_email,))
        self.db_connection.commit()
        PentesterManager.cursor.close()


# Pivot class
class PivotServer:
    pivot_server_count = 0

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        PivotServer.pivot_server_count += 1

    @staticmethod
    def display_count():
        print "Total number of pivot servers: %d" % PivotServer.pivot_server_count

    def display_details(self):
        print "Hostname: ", self.hostname
        print "Username: ", self.username


# PivotServer manager class
class PivotServerManager:
    def __init__(self, db_connection):
        PivotServerManager.cursor = db_connection.cursor()
        self.db_connection = db_connection

    def create_pivot_server(self, pivot_server):
        PivotServerManager.cursor.execute(
            "INSERT INTO pentest.pivot_server (hostname,username,password) VALUES (%s, %s, %s)",
            (pivot_server.hostname, pivot_server.username, pivot_server.password,))
        self.db_connection.commit()
        PivotServerManager.cursor.close()


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