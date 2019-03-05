#!/usr/bin/python
# import libssh2
import argparse
import socket
from socket import inet_aton
import re
import paramiko

parser = argparse.ArgumentParser(description='default ssh port = 22, default output - stdout', formatter_class=lambda prog: argparse.RawTextHelpFormatter(prog, width=200))

def ip_validate(ip, source):
    try:
        inet_aton(ip)
    except socket.error:
        parser = argparse.ArgumentParser(description='Illegal IP address: '+ip+' from '+source)
        parser.print_help()
        exit(-2)

def output(host, connect_checker, system_user, pass_auth, ssh_allow_users, ssh_users_with_pub_key):
    print '='*65
    print '+'+'-'*64
    if 'connected' in connect_checker:
        print '| HOST: '+host
        print '| Connect status: '+connect_checker
        print '+'+'-'*64
        print '| System users: '+str(system_user)
        print '+'+'-'*64
        print '| SSH config:'
        print '| + PasswordAuthentication: '+pass_auth
        print '| + AllowUsers: '+str(ssh_allow_users)
        for key, val in ssh_users_with_pub_key.items():
            print '+'+'-'*64
            print '| Imported pub key for '+key.upper()+': '
            if val == '':
                print '|  - no imported pub key'
            else:
                for i in val:
                    print '|  + '+i
        print '+'+'-'*64
    else:
        print '| HOST: '+host+' Connect status: '+connect_checker
        print '+'+'-'*64


def output_to_file(file, host, connect_checker, system_user, pass_auth, ssh_allow_users, ssh_users_with_pub_key):
    with open(file,'a') as f:
        f.write('+'+'-'*64+'\n')
        if 'connected' in connect_checker:
            f.write('| HOST: '+host+'\n')
            f.write('| Connect status: '+connect_checker+'\n')
            f.write('+'+'-'*64+'\n')
            f.write('| System users: '+str(system_user)+'\n')
            f.write('+'+'-'*64+'\n')
            f.write('| SSH config:'+'\n')
            f.write('| + PasswordAuthentication: '+pass_auth+'\n')
            f.write('| + AllowUsers: '+str(ssh_allow_users)+'\n')
            for key, val in ssh_users_with_pub_key.items():
                f.write('+'+'-'*64+'\n')
                f.write('| Imported pub key for '+key.upper()+': '+'\n')
                if val == '':
                    f.write('|  - no imported pub key'+'\n')
                else:
                    for i in val:
                        f.write('|  + '+i+'\n')
            f.write('+'+'-'*64+'\n')
        else:
            f.write('| HOST: '+host+' Connect status: '+connect_checker+'\n')
            f.write('+'+'-'*64+'\n')
        f.write('\n\n')



def ssh_connect(ip, login, password, key, port):
    client = paramiko.SSHClient()
    # client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key:
            client.connect(ip,port=port,username=login,key_filename=key,auth_timeout=2, timeout=2)
        else:
            client.connect(ip,port=port,username=login,password=password,auth_timeout=2, timeout=2)
    except paramiko.ssh_exception.NoValidConnectionsError:
        return 'Destination port unreacheble,\n| it is possible to block with firewall', None, None
    except socket.timeout:
        return 'Connection timeout', None, None
    except paramiko.ssh_exception.BadAuthenticationType as e:
        return 'Bad authentication type, allowed type:'+str(e.allowed_types[0]), None, None
    except paramiko.ssh_exception.AuthenticationException:
        return 'Authentication failed, incorrect user or password', None, None
    else:
        sudo_flag = False
        session = client.get_transport().open_session()
        session.set_combine_stderr(True)
        session.get_pty()
        session.exec_command('sudo -k cat /etc/passwd')
        stdin = session.makefile('wb', -1)
        stdout = session.makefile('rb', -1)
        stdin.write(password+'\n')
        stdin.flush()
        sudo_check = stdout.read().split('\n')
        # print sudo_check
        if 'not in the sudoers' in sudo_check[2]:
            status = 'connected [warning]:\n| '+sudo_check[2].split('.')[0]+', trying gathering info' 
            return status, client, sudo_flag
        else:
            status = 'connected'
            sudo_flag = True
            return status, client, sudo_flag



def check_host(ssh_cli, password, sudo_flag):
    users = []
    pass_auth = 'False'
    allowusers = []
    imported_pub_key = {}
    if not sudo_flag:
        # print 'CHECK_WITHOUT_SUDO'
        # get sytem users
        stdin, stdout, stderr = ssh_cli.exec_command('cat /etc/passwd')
        all_system_users =  stdout.read().split('\n')
        for user in all_system_users:
            if 'bin/bash' in user:
                users.append(user.split(":")[0])
        # get pub key from connected user
        stdin, stdout, stderr = ssh_cli.exec_command('cat /home/'+login+'/.ssh/authorized_keys')
        raw_pub_keys = stdout.read().split('\n')
        raw_pub_keys = filter(None, raw_pub_keys)
        pub_key_users = []
        for raw_pub_key in raw_pub_keys:
            pub_key_users.append(raw_pub_key.split()[-1:])
        imported_pub_key[login] = pub_key_users[0]
        # print imported_pub_key
        pass_auth = 'Unknown'
        allowusers = ['Unknown']
        # print users, pass_auth, allowusers, imported_pub_key
        return users, pass_auth, allowusers, imported_pub_key
        # print pass_auth
        ssh_cli.close()
    else:
        # get sytem users
        session = ssh_cli.get_transport().open_session()
        session.set_combine_stderr(True)
        session.get_pty()
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
                pass_auth = 'True'
            if 'AllowUsers' in line:
                allowusers = line.split()[1:]
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
            raw_pub_key = filter(None,raw_pub_key)
            # print raw_pub_key
            pub_key_users = []
            if 'No such file' in raw_pub_key[0]:
                imported_pub_key[user]=['No authorized_keys']
                continue
            else:
                for i in raw_pub_key:
                    pub_key_user = i.split('\n')[0].split()[-1:][0]
                    pub_key_users.append(pub_key_user)
            imported_pub_key[user]=pub_key_users
        # print imported_pub_key
        session.close()
        ssh_cli.close()
        # print imported_pub_key
        return users, pass_auth, allowusers, imported_pub_key

if __name__ == "__main__":
    GROUP_MUT1 = parser.add_mutually_exclusive_group()
    GROUP_MUT2 = parser.add_mutually_exclusive_group()
    parser.add_argument('-l', dest='login', help='login for connect')
    parser.add_argument('-p', dest='password', help='password for connect and sudo')
    GROUP_MUT2.add_argument('--key', dest='key', help='path to private key for auth')
    GROUP_MUT1.add_argument('--file', help='file where every line with ip[:port] value')
    GROUP_MUT1.add_argument('--ip', help='single target, you can set custom port: 10.10.10.10:2200')
    parser.add_argument('--output', dest='out_file', help='file to store info about host(s)')

    args = parser.parse_args()
    login = args.login
    password = args.password
    out_file = args.out_file

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
    #host, connect_checker, system_user, pass_auth, ssh_allow_users, ssh_users_with_pub_key
    for ip_addr, port in ip_port_dict.items():
        connect_checker, ssh_client, sudo_flag = ssh_connect(ip_addr,login,password,key,port)
        if connect_checker == 'connected':
            sys_users, pass_auth, allowusers, imported_pub_key = check_host(ssh_client, password, sudo_flag)
            if out_file:
                output_to_file(out_file,ip_addr, connect_checker, sys_users, pass_auth, allowusers, imported_pub_key)
            else:
                output(ip_addr, connect_checker, sys_users, pass_auth, allowusers, imported_pub_key)
            
        elif 'warning' in connect_checker:
            sys_users, pass_auth, allowusers, imported_pub_key = check_host(ssh_client, password, sudo_flag)
            if out_file:
                output_to_file(out_file,ip_addr, connect_checker, sys_users, pass_auth, allowusers, imported_pub_key)
            else:
                output(ip_addr, connect_checker, sys_users, pass_auth, allowusers, imported_pub_key)
        else:
            if out_file:
                output_to_file(out_file,ip_addr, connect_checker, None, None, None, None)
            else:
                output(ip_addr, connect_checker, None, None, None, None)
