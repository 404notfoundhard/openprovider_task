#!/usr/bin/python
import paramiko
# import libssh2
import argparse
import socket
from socket import inet_aton
import re

parser = argparse.ArgumentParser(description='ssh default port = 22', formatter_class=lambda prog: argparse.RawTextHelpFormatter(prog, width=200))
def ip_validate(ip_list, source):
    try:
        line = 0
        for i, val in enumerate(ip_list):
            ip = re.sub(r':[0-9]{2,5}$','',val)
            inet_aton(ip)
    except Exception:
        parser = argparse.ArgumentParser(description='Illegal IP address from '+source)
        parser.print_help()
        exit(-2)

def output(hosts, connect_checker, system_user, pass_auth, ssh_allow_users, ssh_users_with_pub_key):
    # hosts = ['10.10.10.11']
    # connect_checker = 'good'
    # system_user = ['user1','user2']
    # pass_auth = 'ENABLED'
    # ssh_allow_users = ['user1','user2']
    # ssh_users_with_pub_key = {'user1':['service_user','system_user'],'user2':''}
    for i in hosts:
        print '+'+'-'*50
        if 'bad' in connect_checker:
            print '| HOST: '+i+' Connect status: '+connect_checker
            print '+'+'-'*50
            break
        else:
            print '| HOST: '+i+' Connect status: '+connect_checker
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
        print '+'+'-'*50

def ssh_connect(ip,login,password,key):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip,username=login,password=password,auth_timeout=2, timeout=2)
    except paramiko.ssh_exception.NoValidConnectionsError:
        return 'Destination port unreacheble, it is possible to block with firewall.'
    except socket.timeout:
        return 'Connection timeout.'
    except paramiko.ssh_exception.BadAuthenticationType as e:
        return 'Bad authentication type, allowed type:'+str(e.allowed_types[0])
    except paramiko.ssh_exception.AuthenticationException as f:
        return 'Authentication failed'
    except Exception:
        return '-1'    
    
    else:
        client.close()
        return 'good'
        
    stdin, stdout, stderr = client.exec_command('ls -la')
    



def check_host(ip,login,password,key):
    pass

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
    for i,val in enumerate(ip_list):
        if ':' in ip_list[i]:
            continue
        # ip_list[i] = val+':22'
    ip_validate(ip_list, source)

    for i in ip_list:
        aaa = ssh_connect(i,login,password,key)
        print aaa
        print '=============='