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
import getpass
import pickle
import time
import re
import datetime
import multiprocessing

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

    def __init__(self, website_url, webserver_hostname, pivot_server, arachni_host, pentester, tunneling_method):
        self.website_url = website_url
        self.tunnel_method = tunneling_method
        self.pentester = pentester
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
            print "[x] Cricital error occured! Sandbox cannot be created [x]"
            response.raise_for_status()
            sys.exit(1)

    def delete_sandbox(self, sandbox):
        rest_url = "http://kypo.ics.muni.cz:5000/scenario/sandbox/delete/" + sandbox.name
        response = requests.get(rest_url)
        if response.ok:
            print "[*] Sandbox deleted [*]"
            jData = json.loads(response.content)
            print jData

            sandbox = self.s.query(Sandbox).filter_by(name=sandbox.name).first()
            self.s.delete(sandbox)
            self.s.commit()
        else:
            print "[x] Cricital error occured! Sandbox cannot be deleted [x]"
            response.raise_for_status()
            sys.exit(1)

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
            print "[*] Arachni host: " + ArachniHost.hostname + " created [*]"
            rest_url = "http://kypo.ics.muni.cz:5000/scenario/" + sandbox_name + "/host/copy/arachni/" + arachni_host.name + "/" + arachni_host.hostname
            response = requests.get(rest_url)
            if response.ok:
                jData = json.loads(response.content)
                print jData

                self.s.add(arachni_host)
                self.s.commit()
            else:
                print "[x] Cricital error occured! Arachni host: " + ArachniHost.hostname + " cannot be created [x]"
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

    def get_pivot_byid(self, pivot_id):
        pivot_server = self.s.query(PivotServer).filter_by(id=pivot_id).first()
        return pivot_server


# method which prints instructions
def help():
    print "Usage: penetration_test.py   -n <NUMBER> -s <SANDBOX_NAME> -u <USER_EMAIL>"
    print "  -n                         specify the number of websites for penetration test"
    print "  -s                         specify the sandbox name"
    print "  -u                         specify the user email"
    print "  -h                         output help information"	
    print "Examples: "
    print "penetration_test.py -n 1 -s sandbox_name -u user_email@company.com"


# method which checks if the variable is int
def int_try_parse(value):
    try:
        int(value)
        return True
    except ValueError:
        return False


# verify that pivot has a valid format
def validate_pivot(pivot_server):
    error_message = ""
    if not pivot_server.hostname:
        error_message += "\nPivot hostname is empty!"
    if not pivot_server.username:
        error_message += "\nPivot username is empty!"
    if not pivot_server.password:
        error_message += "\nPivot password is empty!"
    if error_message == "":
        return True
    else:
        print error_message
        return False



# verify that testing_subject has a valid format
def validate_testing_subject(testing_subject):
    error_message = ""
    if not testing_subject.webserver_hostname:
        error_message += "\nWeb server is empty!"
    if testing_subject.tunnel_method != "ncat" and testing_subject.tunnel_method != "ssh" and testing_subject.tunnel_method != "socks" and testing_subject.tunnel_method != "vpn":
        print testing_subject.tunnel_method
        error_message += "\nInvalid tunnel method!"
    if not testing_subject.website_url:
        error_message += "\nWeb application URL is empty!"
    if testing_subject.pivot_server == [None]:
        error_message += "\nPivot server not set!"
    elif testing_subject.website_url[:7] != "http://":
        error_message += "\nWeb application URL is not starting with 'http://'!"

    if error_message == "":
        return True
    else:
        print error_message
        print "\n"
        return False


# verify that user eamil has a valid format:
def validate_user_email(user_email):
    if not re.match(r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$", user_email):
        return False
    return True

# method which creates a specified number of websites
def generate_websites(number_of_websites, pentester_id):
    isValid = False
    websites = [None]
    websites_counter = 0
    pivot_server_manager = PivotServerManager(s)
    testing_subject_manager = TestingSubjectManager(s)
    while websites_counter < int(number_of_websites) and isValid is False:
        print "Data for web application %s" % (websites_counter + 1)
        print "--------------------------"
        website_url = raw_input("Web application url: ").strip('\n')
        tunneling_method = raw_input("Tunneling method: ").strip('\n')
        pivot_server = raw_input("Pivot server: ").strip('\n')
        pivot_username = raw_input("Pivot user: ").strip('\n')
        pivot_password = getpass.getpass("Pivot password: ").strip('\n')
        web_server = raw_input("Web server: ").strip('\n')

        pivot_complete = PivotServer(pivot_server,pivot_username,pivot_password)
        if validate_pivot(pivot_complete):
            pivot_server_manager.create_pivot_server(pivot_complete)

        testing_subject = TestingSubject(website_url,web_server,pivot_complete.id,None, pentester_id, tunneling_method)
        if validate_testing_subject(testing_subject):
            testing_subject_manager.create_testing_subject(testing_subject)
            websites.append(testing_subject)
            websites_counter += 1



    # remove the first empty object
    websites.remove(None)
    return websites


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
        for website in websites:
            website.display_details()
    else:
        print "[x] Error occurred. There are no web applications to test [x]"


# method which displays all arachni hosts
def display_arachni_hosts(arachni_hosts):
    if arachni_hosts:

        for arachni_host in arachni_hosts:
            arachni_host.display_details()
    else:
        print "[x] Error occurred. There are no Arachni hosts [x]"


# method which gets the current ip of SMN
def get_smn_ip(sandbox_name):
    rest_url = "http://kypo.ics.muni.cz:5000/scenario/sandbox/ip/" + sandbox_name
    response = requests.get(rest_url)

    if response.ok:
        jData = json.loads(response.content)

        sandbox_ip = jData["ip"]

        return sandbox_ip


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
            if not validate_user_email(user_email):
                print "User email has invalid format! The general format should be used: username@email.com"
                print "\n"
                help()
                sys.exit(1)

        elif option[0] in '-n':
            number_of_websites = option[1]
            if not int_try_parse(number_of_websites):
                print "Number cannot be parsed!"
                print "\n"
                help()
                sys.exit(1)
            if (int(number_of_websites) < 1) or (int(number_of_websites) > 99):
                print "Incorrect number range! Insert number 1-99."
                print "\n"
                help()
                sys.exit(1)
        elif option[0] in '-s':
            sandbox_name = option[1]
        else:
            print "The option does not exist!"
            print "\n"
            help()
            sys.exit(1)

    if number_of_websites == 1:
        print "Insert the data of web application which should be tested!"
    else:
        print "Insert the data of web applications which should be tested!"

    print



    # check if user already exists if not create a new user
    pentester_manager = PentesterManager(s)
    pentester = pentester_manager.get_pentester_byemail(user_email)



    if not pentester:
        pentester = Pentester(user_email)
        pentester_manager.create_pentester(pentester)

    pentester_id = pentester.id

    # generate websites which should be tested
    websites = generate_websites(number_of_websites,pentester_id)

    # check if sandbox already exists if not create a new sandbox
    sandbox_manager = SandboxManager(s)
    sandbox = sandbox_manager.get_sandbox_byname(sandbox_name)
    if not sandbox:
        print "[*] Sandbox is being initiliazed [*]"
        sandbox = Sandbox(sandbox_name)
        sandbox_manager.create_sandbox(sandbox)
        print "[*] Sandbox initialization is complete [*]"
    else:
        print "[*] Sandbox is already initialized [*]"

    # get IP adress of SMN host
    smn_host = get_smn_ip(sandbox_name)

    print "[*] Arachni hosts are being prepared [*]"
    # generate arachni hosts
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

    # establish connection to SMN
    smn_client = establish_smn_connection(smn_host, port, smn_username, smn_password)

    # create empty list for arachni connections
    arachni_clients = [None]

    # establish connection to all arachni hosts
    for x in range(0, len(arachni_hosts)):
        arachni_client = establish_arachni_connection(smn_client, smn_host, arachni_hosts[x],port)
        arachni_clients.append(arachni_client)

    # remove redundant None option
    arachni_clients.remove(None)
    jobs = []
    # perform penetration test
    for x in range (0, len(arachni_clients)):
        perform_test(arachni_clients[x], websites[x],smn_host,smn_client, port)
        #p = multiprocessing.Process(target=perform_test, args=(arachni_hosts[x], websites[x], smn_host, smn_client, port,))
        #jobs.append(p)
        #p.start()


def establish_smn_connection(smn_host, port, smn_username, smn_password):
    print "[*] Trying to establish connection to " + smn_host + " [*]"

    # establish connection to KYPO (SMN)
    try:
        smn_client = paramiko.SSHClient()

        smn_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        smn_client.connect(smn_host, port=port, username=smn_username, password=smn_password)
        print "[*] Connection to " + smn_host + " established [*]"
        smn_client.exec_command("route add -net 10.10.20.0 gw 172.16.1.3 netmask 255.255.255.0")
        smn_client.exec_command("route add -net 10.10.10.0 gw 172.16.1.2 netmask 255.255.255.0")
    except paramiko.AuthenticationException:
        print "[x] Authentication failed when connecting to " + smn_host + " [x]"
        sys.exit(1)

    return smn_client


def establish_arachni_connection(smn_client, smn_host, arachni_host, port):
    while True:
        print "[*] Trying to establish connection to " + arachni_host.hostname + " [*]"
        try:
            transport = smn_client.get_transport()
            destination_addr = (arachni_host.hostname, port)
            local_addr = (smn_host, port)
            channel = transport.open_channel("direct-tcpip", destination_addr, local_addr)
        except Exception:
            continue
        break

    # establish connection to Arachni host
    try:
        arachni_client = paramiko.SSHClient()
        arachni_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        arachni_client.connect(arachni_host.hostname, port=port, username=arachni_host.username, password=arachni_host.password, sock=channel)
        print "[*] Connection to " + arachni_host.hostname + " established [*]"
    except paramiko.AuthenticationException:
        print "[x] Authentication failed when connecting to " + arachni_host.hostname + " [x]"
        sys.exit(1)

    return arachni_client


def establish_pivot_connection(smn_client, smn_host, pivot_server, port):
    while True:
        print "[*] Trying to establish connection to " + pivot_server.hostname + " [*]"
        try:
            transport = smn_client.get_transport()
            destination_addr = (pivot_server.hostname, port)
            local_addr = (smn_host, port)
            channel = transport.open_channel("direct-tcpip", destination_addr, local_addr)
        except Exception:
            continue
        break

    # establish connection to pivot host
    try:
        pivot_client = paramiko.SSHClient()
        pivot_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pivot_client.connect(pivot_server.hostname, port=port, username=pivot_server.username,
                               password=pivot_server.password, sock=channel)
        print "[*] Connection to " + pivot_server.hostname + " established [*]"
    except paramiko.AuthenticationException:
        print "[x] Authentication failed when connecting to " + pivot_server.hostname + " [x]"
        sys.exit(1)

    return pivot_client


def perform_test(arachni_client, testing_subject, smn_host, smn_client, port):
    # prepare command to feed scanner
    arachni_command = ''


    query = s.query(TestingSubject.pivot_server).filter(TestingSubject.website_url == testing_subject.website_url)
    pivot_id = query.scalar()

    pivot_server_manager = PivotServerManager(s)
    pivot_server = pivot_server_manager.get_pivot_byid(pivot_id)

    # establish connection to pivot server
    pivot_client = establish_pivot_connection(smn_client,smn_host,pivot_server,port)

    print "[*] Penetration testing is being initialized [*]"
    if testing_subject.tunnel_method == 'vpn':
        print "[x] Invalid tunneling method [x]"
        sys.exit(1)
    elif testing_subject.tunnel_method == 'socks':
        arachni_client.exec_command("echo 'socks5    127.0.0.1:9150' >> /etc/proxychains.conf")
        arachni_client.exec_command('ssh -fN -o StrictHostKeyChecking=no -D 127.0.0.1:9150 pivotserver@10.10.20.7')
        arachni_command = 'Scanner/arachni-1.4-0.5.10/bin/arachni --checks=xss --scope-page-limit 5 ' + testing_subject.website_url + ' --http-proxy socks5://127.0.0.1:9150'

    elif testing_subject.tunnel_method == 'ncat':
        pivot_client.exec_command("ncat --listen --proxy-type http 10.10.20.7 8080 &")

        arachni_command = 'Scanner/arachni-1.4-0.5.10/bin/arachni --checks=xss --scope-page-limit 5 ' + testing_subject.website_url + ' --http-proxy ' + pivot_server.hostname+':8080'
    elif testing_subject.tunnel_method == 'ssh':
       arachni_client.exec_command('ssh -fN -o StrictHostKeyChecking=no -L 8080:10.10.20.14:80 pivotserver@10.10.20.7')
       arachni_command = 'Scanner/arachni-1.4-0.5.10/bin/arachni --checks=xss --scope-page-limit 5 ' + testing_subject.website_url + ' --http-proxy 127.0.0.1:8080'

    else:
        print "[x] Invalid tunneling method [x]"
        sys.exit(1)

    stdin, stdout, stderr= arachni_client.exec_command(arachni_command)

    while not stdout.channel.exit_status_ready():
        if stdout.channel.recv_ready():
            rl, wl, xl = select.select([stdout.channel], [], [], 0.0)
            if len(rl) > 0:
                print stdout.channel.recv(1024)

				
if __name__ == '__main__':
    main()

