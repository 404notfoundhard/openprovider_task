#!/usr/bin/python
import paramiko
# import libssh2
import argparse
import socket
from socket import inet_aton
import re

parser = argparse.ArgumentParser(description='ssh default port = 22', formatter_class=lambda prog: argparse.RawTextHelpFormatter(prog, width=200))
def ip_validate(ip, source):
    try:
        inet_aton(ip)
    except Exception:
        parser = argparse.ArgumentParser(description='Illegal IP address: '+ip+' from '+source)
        parser.print_help()
        exit(-2)

def output(host, connect_checker, system_user, pass_auth, ssh_allow_users, ssh_users_with_pub_key):
    # hosts = ['10.10.10.11']
    # connect_checker = 'good'
    # system_user = ['user1','user2']
    # pass_auth = 'ENABLED'
    # ssh_allow_users = ['user1','user2']
    # ssh_users_with_pub_key = {'user1':['service_user','system_user'],'user2':''}
    print '+'+'-'*102
    if 'connected' in connect_checker:
        print '| HOST: '+host+' Connect status: '+connect_checker
        print '| System users: '+str(system_user)
        print '| SSH config:'
        print '| + PasswordAuthentication: '+pass_auth
        print '| + AllowUsers: '+str(ssh_allow_users)
        for key, val in ssh_users_with_pub_key.items():
            print '| Imported pub key for '+key.upper()+': '
            if val == '':
                print '|  - no imported pub key'
            else:
                for i in val:
                    print '|  + '+i
        print '+'+'-'*102
    else:
        print '| HOST: '+host+' Connect status: '+connect_checker
        print '+'+'-'*102

def ssh_connect(ip,login,password,key,port):
    client = paramiko.SSHClient()
    # client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip,port=port,username=login,password=password,auth_timeout=2, timeout=2)
    except paramiko.ssh_exception.NoValidConnectionsError:
        return 'Destination port unreacheble, it is possible to block with firewall', None
    except socket.timeout:
        return 'Connection timeout', None
    except paramiko.ssh_exception.BadAuthenticationType as e:
        return 'Bad authentication type, allowed type:'+str(e.allowed_types[0]), None
    except paramiko.ssh_exception.AuthenticationException:
        return 'Authentication failed, incorrect user or password', None
    else:
        return 'connected', client
        
    # stdin, stdout, stderr = client.exec_command('ls -la')
    



def check_host(ssh_cli, password):
    users = []
    pass_auth = False
    AllowUsers = []
    imported_pub_key = {}
    # get sytem users
    session = ssh_cli.get_transport().open_session()
    session.set_combine_stderr(True)
    session.get_pty()
    # TODO: check if sudo exist
    session.exec_command('sudo -k cat /etc/passwd')
    stdin = session.makefile('wb', -1)
    stdout = session.makefile('rb', -1)
    stdin.write(password+'\n')
    stdin.flush()
    all_system_users =  stdout.read().split('\n')
    for user in all_system_users:
        if 'bin/bash' in user:
            users.append(user.split(":")[0])
    # get Auth_pass and AllowUsers value from sshd_config
    session = ssh_cli.get_transport().open_session()
    session.set_combine_stderr(True)
    session.get_pty()
    session.exec_command('sudo -k cat /etc/ssh/sshd_config')
    stdin = session.makefile('wb', -1)
    stdout = session.makefile('rb', -1)
    stdin.write(password+'\n')
    stdin.flush()
    sshd_config = stdout.read().split('\n')
    for line in sshd_config:
        if 'PasswordAuthentication yes' in line:
            pass_auth = True
        if 'AllowUsers' in line:
            AllowUsers = line.split()[1:]
    # get pub key from user
    for user in users:
        session = ssh_cli.get_transport().open_session()
        session.set_combine_stderr(True)
        session.get_pty()
        session.exec_command('sudo -k cat /home/'+user+'/.ssh/authorized_keys')
        stdin = session.makefile('wb', -1)
        stdout = session.makefile('rb', -1)
        stdin.write(password+'\n')
        stdin.flush()
        raw_pub_key = stdout.read().split('\n')[2:]
        # print a[2:]
        raw_pub_key = filter(None,raw_pub_key)
        # print raw_pub_key
        # print '#'*20+user+'#'*20
        pub_key_users = []
        if 'No such file' in raw_pub_key[0]:
            imported_pub_key[user]='No authorized_keys'
        else:
            for i in raw_pub_key:
                pub_key_user = i.split('\n')[0].split()[-1:][0]
                pub_key_users.append(pub_key_user)
                # imported_pub_key[user] = key.split()[-1:][0]
        imported_pub_key[user]=pub_key_users
    print imported_pub_key
        # print stdout.read()
        # imported_pub_key.append(stdout.read().split()[7])
    # print imported_pub_key
    # print stderr.read()
    session.close()
    ssh_cli.close()

if __name__ == "__main__":
    group_mut1 = parser.add_mutually_exclusive_group()
    group_mut2 = parser.add_mutually_exclusive_group()
    parser.add_argument('-l', dest='login', help='login for connect')
    group_mut2.add_argument('-p', dest='password', help='password for connect')
    group_mut2.add_argument('-k', dest='key', help='path to private key for auth')
    group_mut1.add_argument('--file', help='file where every line with ip[:port] value')
    group_mut1.add_argument('--ip', help='single target, you can set custom port: 10.10.10.10:2200')
    parser.add_argument('--output',help='file to store info about host(s)')

    

    args = parser.parse_args()
    login = args.login
    password = args.password
    key = ''
    if args.key:
        key = args.key
    
    ip_list = []
    if args.ip:
        source = 'string'
        ip_list.append(args.ip)
    elif args.file:
        source = 'file'
        try:
            with open(args.file,'r') as f:
                ip_list = f.read().split('\n')
        except Exception as e:
            parser = argparse.ArgumentParser(description=str(e))
            parser.print_help()
            exit(-1)
        
    else:
        parser = argparse.ArgumentParser(description='show help')
        parser.print_help()
        exit(-1)

    ip_list = filter(None, ip_list)
    ip_port_dict= {}
    for i,val in enumerate(ip_list):
        if ':' in ip_list[i]:
            # print val
            port = re.search(r'(?<=:)[0-9]{2,5}$',val).group(0)
            ip = re.sub(r':[0-9]{2,5}$','',val)
            ip_validate(ip, source)
            ip_port_dict[ip] = port
        else:
            port = '22'
            ip_validate(val, source)
            ip_port_dict[val] = port

    for ip_addr, port in ip_port_dict.items():
        connect_checker, ssh_client = ssh_connect(ip_addr,login,password,key,port)
        if connect_checker != 'connected':
            output(ip_addr,connect_checker,None,None,None,None)
        else:
            check_host(ssh_client, password)
