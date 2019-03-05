# Environment:
### Example usage:  
```
ssh_checker.py -l service_user -p pass --key ansible-create-env/files/my_user2  --file host_list --output out.txt
```
```
usage: ssh_checker.py [-h] [-l LOGIN] [-p PASSWORD] [--key KEY] [--file FILE | --ip IP] [--output OUT_FILE]

default ssh port = 22, default output - stdout

optional arguments:
  -h, --help         show this help message and exit
  -l LOGIN           login for connect
  -p PASSWORD        password for connect and sudo
  --key KEY          path to private key for auth
  --file FILE        file where every line with ip[:port] value
  --ip IP            single target, you can set custom port: 10.10.10.10:2200
  --output OUT_FILE  file to store info about host(s)
```
- requirements:\
Vagrant  
ansible  
cryptography==2.4.2  
argparse  
paramiko  

- env:  
password for all users: pass 

- Create environment command:  
```vagrant up```

 - ssh_key_users:
   - my_user1
   - my_user2
   - hacker
- Machine:
   - server 1: # icmp_port_unreachable (firewall reject)

   - server 2: # connection_timeout

   - server 3: # Password auth enabled
       - users: service_user, user1, user2
       - AllowUsers: serviceuser, user1
       - pub_key_imported_for: serviceuser, user1, user2
       - imported_ssh_key_users: all
       - PasswordAuthorization: yes

   - server 4: # Password auth disabled and allow only service_user
       - users: service_user, user2
       - AllowUsers: serviceuser
       - pub_key_imported_for: serviceuser, user2
       - imported_ssh_key_users: my_user2
       - PasswordAuthorization: no 

   - server 5: # Password auth enabled, but without sudo privileges
       - users: service_user, user1, user2
       - AllowUsers: serviceuser, user1
       - pub_key_imported_for: serviceuser, user1, user2
       - imported_ssh_key_users: all
       - PasswordAuthorization: yes
