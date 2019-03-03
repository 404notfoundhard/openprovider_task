#!/usr/bin/python
import paramiko
import argparse
import socket
from socket import inet_aton
import re

parser = argparse.ArgumentParser(description='default port 22')

def ip_validate(ip_list, source):
    try:
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
            print '| HOST: '+i+' Connect: '+connect_checker
            print '+'+'-'*50
            break
        else:
            print '| HOST: '+i+' Connect: '+connect_checker
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


if __name__ == "__main__":
    group_mut = parser.add_mutually_exclusive_group()
    group_mut.add_argument('--file', help='File where every line with ip[:port] value')
    group_mut.add_argument('--ip', help='Single target, you can set custom port: 10.10.10.10:2200',type=str)
    parser.add_argument('output',help='file to store info about host(s)')
    

    args = parser.parse_args()
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
        ip_list[i] = val+':22'
    ip_validate(ip_list, source)


#     dicc = {'asd':'test'}
#     host = '10.10.10.10'
#     connect_checker = 'good'
#     system_user = ['user1','user2']
#     pass_auth = 'ENABLED'
#     users_pub_key = ['hacker','test']
#     print('''+----------------------------------------
# | HOST: {0}
# | connect check: {1}
# | System users: {2}
# | SSH config: 
# | + Password auth: {3}
# | + AllowUsers: {4}
# | {5} Imported pub key from(count {6}):
# | {7}
# +----------------------------------------
# '''.format(dicc, connect_checker,system_user,pass_auth,system_user,system_user[0],2,users_pub_key))
