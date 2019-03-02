Vagrant.configure("2") do |config|

    config.vm.provider :virtualbox do |v|
      v.memory = 512
    end
  
    (1..4).each do |i|
        config.vm.define "server-#{i}" do |db|
            db.vm.box = "centos/7"
            db.vm.hostname = "server-#{i}"
            db.vm.network :private_network, ip: "10.10.10.1#{i}"
  
            db.vm.provision "ansible" do |ansible|
                ansible.playbook = "ansible-create-env/create-env.yml"
            end
        end
    end
end
#     config.vm.define "server2" do |app|
#       app.vm.box = "ubuntu/xenial64"
#       app.vm.hostname = "appserver"
#       app.vm.network :private_network, ip: "10.10.10.20"
  
#       app.vm.provision "ansible" do |ansible|
#         ansible.playbook = "playbooks/site.yml"
#         ansible.groups = {
#         "app" => ["appserver"],
#         "app:vars" => { "db_host" => "10.10.10.10"}
#         }
#         ansible.extra_vars = {
#             "deploy_user" => "vagrant",
#             "nginx_sites" => {
#                 "default" => [
#                     "listen 80",
#                      "server_name reddit",
#                      "location / { proxy_pass http://127.0.0.1:9292; }"
#                 ]
#             }
#         }
#       end
#     end
#   end
