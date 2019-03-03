# Environment:
- requirements:\
Vagrant\
ansible

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
