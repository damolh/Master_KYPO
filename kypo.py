import paramiko
import getopt
import sys
import json
import requests
from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import random
import getpass
import pickle
import time
import re
import datetime
import smtplib
import Queue
import threading

# SQL Alchemy mapping
Base = declarative_base()
engine = create_engine('',echo=False)
metadata = MetaData(bind=engine)
session = sessionmaker()
session.configure(bind=engine)
s = session()

### Section with class definition and their managers ###


# testing subject class
class TestingSubject(Base):
    __table__ = Table('testing_subject', metadata, autoload=True, schema="pentest")

    def __init__(self, web_application, pivot_server, pentester, tunneling_method):
        self.tunnel_method = tunneling_method
        self.pentester_id = pentester
        self.pivot_server_id = pivot_server
        self.web_application_id = web_application


# TestingSubject manager class
class TestingSubjectManager:
    def __init__(self, s):
        self.s = s

    def create_testing_subject(self, testing_subject):
        self.s.add(testing_subject)
        self.s.commit()

    def delete_testing_subject(self, testing_subject):
        self.s.delete(testing_subject)
        self.s.commit()
        self.s.flush()


# web server class
class WebServer(Base):
    __table__ = Table('web_server', metadata, autoload=True, schema="pentest")

    def __init__(self, hostname):
        self.hostname = hostname


# WebServer manager class
class WebServerManager:
    def __init__(self, s):
        self.s = s

    def create_web_server(self, web_server):
        self.s.add(web_server)
        self.s.commit()

    def delete_web_server(self, web_server):
        query = s.query(WebApplication.id).filter(WebApplication.web_server_id == web_server.id)
        web_application_id = query.scalar()
        if not web_application_id:
            self.s.delete(web_server)
            self.s.commit()
            self.s.flush()
            print "[+] Web server '" + web_server.hostname + "' was deleted [+]"
        else:
            print "[!] Web server '" + web_server.hostname + "' was not deleted. Other application is being tested [!]"

    def get_web_server_byid(self, web_server_id):
        web_server = self.s.query(WebServer).filter_by(id=web_server_id).first()
        return web_server

    def get_web_server_byhostname(self, hostname):
        web_server = self.s.query(WebServer).filter_by(hostname=hostname).first()
        return web_server


# web application class
class WebApplication(Base):
    __table__ = Table('web_application', metadata, autoload=True, schema="pentest")

    def __init__(self, url, web_server):
        self.url = url
        self.web_server_id = web_server


# WebApplication manager class
class WebApplicationManager:
    def __init__(self, s):
        self.s = s

    def create_web_application(self, web_application):
        self.s.add(web_application)
        self.s.commit()

    def delete_web_application(self, web_application):
        self.s.delete(web_application)
        self.s.commit()
        self.s.flush()

    def get_web_application_byid(self, web_application_id):
        web_application = self.s.query(WebApplication).filter_by(id=web_application_id).first()
        return web_application


# Sandbox class
class Sandbox:
    def __init__(self, name):
        self.name = name


# Sandbox manager class
class SandboxManager:
    def create_sandbox(self, sandbox_name):
        rest_url = "http://kypo.ics.muni.cz:5000/scenario/sandbox/load/" + sandbox_name + "/konicek-vizvary.json"
        response = requests.get(rest_url)
        if response.ok:
            jData = json.loads(response.content)
            print jData
        else:
            print "[-] Sandbox '" + sandbox_name + "' cannot be created [-]"
            response.raise_for_status()
            sys.exit(1)

    def delete_sandbox(self, sandbox_name):
        rest_url = "http://kypo.ics.muni.cz:5000/scenario/sandbox/delete/" + sandbox_name
        response = requests.get(rest_url)
        if response.ok:
            print "[+] Sandbox '" + sandbox_name + "' successfully deleted [+]"
            jData = json.loads(response.content)
            print jData
        else:
            print "[-] Sandbox '" + sandbox_name + "' cannot be deleted [-]"
            response.raise_for_status()
            sys.exit(1)

    def get_sandbox_ip(self, sandbox_name):
        rest_url = "http://kypo.ics.muni.cz:5000/scenario/sandbox/ip/" + sandbox_name
        response = requests.get(rest_url)
        if response.ok:
            jData = json.loads(response.content)
            sandbox_ip = jData["ip"]
            return sandbox_ip


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
                print "[+] Arachni host '" + ArachniHost.hostname + "' was created [+]"
                self.s.add(arachni_host)
                self.s.commit()
            else:
                print "[-] Arachni host '" + ArachniHost.hostname + "' cannot be created [-]"
                response.raise_for_status()
                sys.exit(1)

    def get_arachni_host_byhostname(self, hostname):
        arachni_host = self.s.query(ArachniHost).filter_by(hostname=hostname).first()
        return arachni_host

    def get_arachni_host_username(self, username):
        arachni_host = self.s.query(ArachniHost).filter_by(username=username).first()
        return arachni_host

    def delete_arachni_host(self, arachni_host):
        # delete function is not actually implemented in KYPO, so the code removes only database records
        self.s.delete(arachni_host)
        self.s.commit()


# Pivot class
class PivotServer(Base):
    __table__ = Table('pivot_server', metadata, autoload=True, schema="pentest")

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password


# PivotServer manager class
class PivotServerManager:
    def __init__(self, s):
        self.s = s

    def create_pivot_server(self, pivot_server):
        s.add(pivot_server)
        s.commit()

    def get_pivot_server_byhostname(self, hostname):
        pivot_server = self.s.query(PivotServer).filter_by(hostname=hostname).first()
        return pivot_server

    def get_pivot_byid(self, pivot_id):
        pivot_server = self.s.query(PivotServer).filter_by(id=pivot_id).first()
        return pivot_server

    def delete_pivot_byid(self, pivot_id):
        query = s.query(TestingSubject).filter(TestingSubject.pivot_server_id == pivot_id)
        testing_subject_id = query.scalar()
        pivot_server = self.get_pivot_byid(pivot_id)
        if not testing_subject_id:
            self.s.delete(pivot_server)
            self.s.commit()
            print "[+] Pivot server '" + pivot_server.hostname + "' was deleted [+]"
        else:
            print "[!] Pivot server '" + pivot_server.hostname + "' was not deleted. Other application is being tested [!]"


# SMTPServer class
class SMTPServer:
    def __init__(self, smtp_server, smtp_login, smtp_password, smtp_user):
        self.smtp_server = smtp_server
        self.smtp_login = smtp_login
        self.smtp_password = smtp_password
        self.smtp_user = smtp_user


### Initialization of managers ###

testing_subject_manager = TestingSubjectManager(s)
arachni_host_manager = ArachniHostManager(s)
pivot_server_manager = PivotServerManager(s)
web_application_manager = WebApplicationManager(s)
web_server_manager = WebServerManager(s)
sandbox_manager = SandboxManager()


### Section related to connection establishment

def establish_smn_connection(smn_host, port, smn_username, smn_password):
    print "[*] Trying to establish connection to " + smn_host + " [*]"

    # establish connection to KYPO (SMN)
    try:
        smn_client = paramiko.SSHClient()
        smn_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        smn_client.connect(smn_host, port=port, username=smn_username, password=smn_password)
        print "[+] Connection to " + smn_host + " established [+]"
        smn_client.exec_command("route add -net 10.10.20.0 gw 172.16.1.3 netmask 255.255.255.0")
        smn_client.exec_command("route add -net 10.10.10.0 gw 172.16.1.2 netmask 255.255.255.0")
    except paramiko.AuthenticationException:
        print "[-] Authentication failed when connecting to " + smn_host + " [-]"
        sys.exit(1)

    return smn_client


def establish_arachni_connection(smn_client, smn_host, arachni_host, port):
    while True:
        print "[*] Trying to establish connection to " + arachni_host.hostname + " [*]"
        time.sleep(15)
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
        print "[+] Connection to " + arachni_host.hostname + " established [+]"
    except paramiko.AuthenticationException:
        print "[!] Authentication failed when connecting to " + arachni_host.hostname + " [!]"
        sys.exit(1)

    return arachni_client


def establish_pivot_connection(smn_client, smn_host, pivot_server, port):
    while True:
        print "[*] Trying to establish connection to " + pivot_server.hostname + " [*]"
        time.sleep(15)
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
        print "[+] Connection to " + pivot_server.hostname + " established [+]"
    except paramiko.AuthenticationException:
        print "[!] Authentication failed when connecting to " + pivot_server.hostname + " [!]"
        sys.exit(1)

    return pivot_client


### Section where is the actual penetration test performed

def perform_test(arachni_client, testing_subject, smn_client, smn_host, port, smtp_server, pentester, q):
    # prepare command to feed scanner
    arachni_command = ''

    # get pivot server specific for penetration test
    pivot_server = pivot_server_manager.get_pivot_byid(testing_subject.pivot_server_id)

    # establish connection to pivot server
    pivot_client = establish_pivot_connection(smn_client, smn_host, pivot_server, port)

    # get web application specific for penetration test
    web_application = web_application_manager.get_web_application_byid(testing_subject.web_application_id)

    # get web server specific for penetration test
    web_server = web_server_manager.get_web_server_byid(web_application.web_server_id)

    # get item from queue
    q.get()

    print "[*] Penetration testing is in progress [*]"
    print "[*] Pivot server hostname being used is '" + pivot_server.hostname + "' [*]"
    print "[*] Web server hostname being used is '" + web_server.hostname + "' [*]"
    print "[*] Web application URL being scanned is '" + web_application.url + "' [*]"
    print "[*] Tunneling method was set to '" + testing_subject.tunnel_method + "' [*]"

    # vpn technique
    if testing_subject.tunnel_method == 'vpn':
        print "[!] Invalid tunneling method [!]"
        sys.exit(1)

    # socks technique
    elif testing_subject.tunnel_method == 'socks':
        arachni_client.exec_command("echo 'socks5    127.0.0.1:9150' >> /etc/proxychains.conf")
        arachni_client.exec_command('ssh -fN -o StrictHostKeyChecking=no -D 127.0.0.1:9150 ' + pivot_server.username + '@' + pivot_server.hostname)
        arachni_command = 'Scanner/arachni-1.4-0.5.10/bin/arachni --checks=xss --scope-page-limit 5 ' + web_application.url + ' --http-proxy socks5://127.0.0.1:9150'

    # ncat technique
    elif testing_subject.tunnel_method == 'ncat':
        pivot_client.exec_command("ncat --listen --proxy-type http " + pivot_server.hostname + " 8080 &")
        arachni_command = 'Scanner/arachni-1.4-0.5.10/bin/arachni --checks=xss --scope-page-limit 10 ' + web_application.url + ' --http-proxy ' + pivot_server.hostname+':8080'

    # ssh technique
    elif testing_subject.tunnel_method == 'ssh':
       arachni_client.exec_command('ssh -fN -o StrictHostKeyChecking=no -L 8080:'+ web_server.hostname +':80 ' + pivot_server.username + '@' + pivot_server.hostname)
       arachni_command = 'Scanner/arachni-1.4-0.5.10/bin/arachni ' + web_application.url + ' --http-proxy 127.0.0.1:8080'

    else:
        print "[x] Invalid tunneling method [x]"
        sys.exit(1)

    current_time = datetime.datetime.now().isoformat()

    log_text_file = "arachni_log_" + web_application.url[7:] + "_" + current_time + ".log"
    report_text_file = "arachni_report_" + web_application.url[7:] + "_" + current_time + ".txt"

    # read arachni output
    stdin, stdout, stderr= arachni_client.exec_command(arachni_command)

    # store the arachni output to the log file
    net_dump = stdout.readlines()
    pickle.dump(net_dump, open(log_text_file, 'wb'))

    # generate txt report
    arachni_client.exec_command("Scanner/arachni-1.4-0.5.10/bin/arachni_reporter /home/pentester/*.afr --reporter=txt:outfile=/home/pentester/final_report.txt")
    time.sleep(2)
    stdin, stdout, stderr = arachni_client.exec_command('cat /home/pentester/final_report.txt')

    # store the arachni report to the report file
    net_dump2 = stdout.readlines()
    pickle.dump(net_dump2, open(report_text_file, 'wb'))

    print "[*] Penetration test for '" + web_application.url + "' has completed [*]"
    # remove the finished objects
    testing_subject_manager.delete_testing_subject(testing_subject)
    web_application_manager.delete_web_application(web_application)
    web_server_manager.delete_web_server(web_server)
    pivot_server_manager.delete_pivot_byid(testing_subject.pivot_server_id)

    # send notification to the user that test is completed
    send_notification(smtp_server.smtp_server, smtp_server.smtp_user, smtp_server.smtp_password, smtp_server.smtp_user, pentester.email)

    rows = s.query(TestingSubject).filter(TestingSubject.pentester_id == pentester.id).count()
    if rows == 1:
        print "[*] Penetration testing still in progress. 1 web application remains [*]"
    elif rows > 1:
        print "[*] Penetration testing still in progress. " + str(rows) + " web applications remain [*]"

    # mark item in queue as done
    q.task_done()


### Section with general methods ###


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
        error_message += "\n[!] Pivot hostname is empty [!]"
    if not pivot_server.username:
        error_message += "\n[!] Pivot username is empty [!]"
    if not pivot_server.password:
        error_message += "\n[!] Pivot password is empty [!]"
    if error_message == "":
        return True
    else:
        print error_message
        return False


# verify that testing_subject has a valid format
def validate_testing_subject(testing_subject):
    error_message = ""
    if testing_subject.tunnel_method != "ncat" and testing_subject.tunnel_method != "ssh" and testing_subject.tunnel_method != "socks" and testing_subject.tunnel_method != "vpn":
        print testing_subject.tunnel_method
        error_message += "\n[!] Invalid tunnel method [!]"

    if error_message == "":
        return True
    else:
        print error_message
        print "\n"
        return False


# verify that web application has a valid format
def validate_web_application(web_application):
    error_message = ""
    if web_application.url[:7] != "http://" or not web_application.url:
        error_message += "\n[!] Web application URL is not starting with 'http://' [!]"

    if error_message == "":
        return True
    else:
        print error_message
        print "\n"
        return False


# verify that web server has a valid format
def validate_web_server(web_server):
    error_message = ""
    if not web_server.hostname:
        error_message += "\n[!] Web server is empty [!]"

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
def generate_testing_subjects(number_of_websites,pentester_id):
    isValid = False
    testing_subjects = [None]
    testing_subject_counter = 0

    while testing_subject_counter < int(number_of_websites) and isValid is False:
        print
        print "Data for web application %s" % (testing_subject_counter + 1)
        print "--------------------------"

        website_url = raw_input("Web application url: ").strip('\n')
        tunneling_method = raw_input("Tunneling method: ").strip('\n')
        pivot_server = raw_input("Pivot server: ").strip('\n')
        pivot_username = raw_input("Pivot user: ").strip('\n')
        pivot_password = getpass.getpass("Pivot password: ").strip('\n')
        web_server = raw_input("Web server: ").strip('\n')

        web_server_complete = WebServer(web_server)
        pivot_complete = PivotServer(pivot_server, pivot_username, pivot_password)

        pivot_server_db = pivot_server_manager.get_pivot_server_byhostname(pivot_server)
        if pivot_server_db:
            pivot_server_id = pivot_server_db.id
        else:
            pivot_server_manager.create_pivot_server(pivot_complete)
            pivot_server_id = pivot_complete.id

        web_server_db = web_server_manager.get_web_server_byhostname(web_server)
        if (web_server_db):
            web_server_id = web_server_db.id
        else:
            web_server_manager.create_web_server(web_server_complete)
            web_server_id = web_server_complete.id



        # initialize the objects based on the user input



        web_application_complete = WebApplication(website_url, web_server_id)
        web_application_manager.create_web_application(web_application_complete)



        testing_subject = TestingSubject(web_application_complete.id, pivot_server_id, pentester_id,
                                         tunneling_method)

        # validate user input and create objects if they pass validation
        if validate_web_server(web_server_complete) and validate_web_application(web_application_complete) and validate_testing_subject(testing_subject) and validate_pivot(pivot_complete):


            testing_subject_manager.create_testing_subject(testing_subject)
            testing_subjects.append(testing_subject)
            testing_subject_counter += 1

    # remove the first empty object
    testing_subjects.remove(None)
    return testing_subjects


# method which creates a specified number of arachni hosts
def generate_arachni_hosts(number_of_hosts, sandbox_name):
    arachni_hosts = [None]

    # get arachni host which is defined in configuration file
    default_arachni_host = arachni_host_manager.get_arachni_host_byhostname("10.10.10.4")

    # if one arachni is needed, it is taken just from configuration file
    if (not default_arachni_host) and (int(number_of_hosts) == 1):
        default_arachni_host = ArachniHost('10.10.10.4', 'pentester', 'pentest', 'arachni')
        arachni_host_manager.create_arachni_host(default_arachni_host,sandbox_name)
        arachni_hosts.append(default_arachni_host)
        arachni_hosts.remove(None)
        return arachni_hosts

    # if more than one arachni is needed use the one in configuration file and generate the rest of them
    elif (not default_arachni_host) and (int(number_of_hosts) > 1):
        default_arachni_host = ArachniHost('10.10.10.4', 'pentester', 'pentest', 'arachni')
        arachni_host_manager.create_arachni_host(default_arachni_host, sandbox_name)
        arachni_hosts.append(default_arachni_host)
        hostname = ''

        for x in range(0, (int(number_of_hosts)-1)):
            arachni_exitst = True
            while(arachni_exitst):
                # generate random IP addresses
                host_ip = random.SystemRandom().randint(0,255)
                hostname = "10.10.10.%d" % host_ip
                test_arachni = arachni_host_manager.get_arachni_host_byhostname(hostname)

                if not test_arachni:
                    arachni_exitst = False
            name = default_arachni_host.name + "%d" % host_ip

            arachni_host = ArachniHost(hostname, default_arachni_host.username, default_arachni_host.password, name)
            arachni_host_manager.create_arachni_host(arachni_host, sandbox_name)
            arachni_hosts.append(arachni_host)

    # do not use arachni from configuration file and generate all of them
    else:
        for x in range(0, int(number_of_hosts)):
            arachni_exitst = True
            while (arachni_exitst):
                # generate random IP addresses
                host_ip = random.SystemRandom().randint(0, 255)
                hostname = "10.10.10.%d" % host_ip
                test_arachni = arachni_host_manager.get_arachni_host_byhostname(hostname)

                if not test_arachni:
                    arachni_exitst = False
            name = default_arachni_host.name + "%d" % host_ip

            arachni_host = ArachniHost(hostname, default_arachni_host.username, default_arachni_host.password, name)
            arachni_host_manager.create_arachni_host(arachni_host, sandbox_name)
            arachni_hosts.append(arachni_host)

    # remove the first empty object
    arachni_hosts.remove(None)
    return arachni_hosts


# method which sends notification to user that the test is completed
def send_notification(smtp_server, smtp_username, smtp_password, from_address, to_address):
    message = "\r\n".join([
        "From: " + smtp_username,
        "To: " + to_address,
        "Subject: KYPO: Penetration test for completed",
        "",
        "test started at, test finished at, url was, see attachment"
    ])

    try:
        server_ssl = smtplib.SMTP_SSL(smtp_server, 465)
        server_ssl.ehlo()
        server_ssl.login(smtp_username, smtp_password)
        server_ssl.sendmail(from_address, to_address, message)
        server_ssl.close()
        print "[*] Email successfully sent to " + to_address + " [*]"
    except:
        print "[!] Failed to send email to " + to_address + " [!]"


# main method
def main():
    # check the correct number of parameters
    if len(sys.argv[1:]) < 1:
        help()
        sys.exit(1)

    # definition of basic variables
    smn_username = ''
    smn_password = ''
    port = 22
    number_of_websites = ''
    sandbox_name = ''
    user_email = ''
    smtp_server = SMTPServer("smtp.gmail.com", "kypotesting@gmail.com", "", "kypotesting@gmail.com")

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
                print "[-] User email has invalid format! The general format should be used: username@email.com [-]"
                print "\n"
                help()
                sys.exit(1)

        elif option[0] in '-n':
            number_of_websites = option[1]
            if not int_try_parse(number_of_websites):
                print "[!] Number cannot be parsed [!]"
                print "\n"
                help()
                sys.exit(1)
            if (int(number_of_websites) < 1) or (int(number_of_websites) > 99):
                print "[!] Incorrect number range! Insert number 1-99 [!]"
                print "\n"
                help()
                sys.exit(1)
        elif option[0] in '-s':
            sandbox_name = option[1]
        else:
            print "[!] The option does not exist [!]"
            print "\n"
            help()
            sys.exit(1)

    print "[*] Initialization of subjects to test [*]"

    # check if user already exists if not create a new user
    pentester_manager = PentesterManager(s)
    pentester = pentester_manager.get_pentester_byemail(user_email)

    if not pentester:
        pentester = Pentester(user_email)
        pentester_manager.create_pentester(pentester)

    #pentester_id = pentester.id

    # generate websites which should be tested
    testing_subjects = generate_testing_subjects(number_of_websites, pentester.id)

    # clear terminal window
    sys.stderr.write("\x1b[2J\x1b[H")

    # check if sandbox already exists if not create a new sandbox
    if not sandbox_manager.get_sandbox_ip(sandbox_name):
        print "[*] Sandbox is being initiliazed [*]"
        sandbox_manager.create_sandbox(sandbox_name)
        print "[+] Sandbox initialization is complete [+]"
    else:
        print "[*] Sandbox is already initialized [*]"

    # get IP adress of SMN host
    smn_host = sandbox_manager.get_sandbox_ip(sandbox_name)

    print "[*] Arachni hosts are being prepared [*]"
    # generate arachni hosts
    arachni_hosts = generate_arachni_hosts(number_of_websites, sandbox_name)

    # establish connection to SMN
    smn_client = establish_smn_connection(smn_host, port, smn_username, smn_password)

    # create empty list for arachni connections
    arachni_clients = [None]

    # setup queue for multi threaded operations
    q = Queue.Queue()

    # establish connection to all arachni hosts
    for x in range(0, len(arachni_hosts)):
        arachni_client = establish_arachni_connection(smn_client, smn_host, arachni_hosts[x],port)
        arachni_clients.append(arachni_client)

        # insert arachni client to the queue
        q.put(arachni_client)

    # remove redundant None option
    arachni_clients.remove(None)

    # perform penetration test
    for x in range (0, len(arachni_clients)):
        # establish multiple threads
        t = threading.Thread(target=perform_test, args=(arachni_clients[x], testing_subjects[x], smn_client, smn_host, port, smtp_server, pentester, q,))
        t.daemon = True
        t.start()

    # wait until all theads complete their job
    q.join()

    # delete arachni hosts
    for x in range(0, len(arachni_hosts)):
        arachni_host_manager.delete_arachni_host(arachni_hosts[x])

    # check if there is active arachni host, if not delete sandbox
    if not arachni_host_manager.get_arachni_host_username("pentester"):
        #sandbox_manager.delete_sandbox(sandbox_name)
        print "[+] Sandbox was deleted [+]"
    else:
        print "[!] Sandbox cannot be deleted. Active Arachni hosts found [!]"


if __name__ == '__main__':
    main()

