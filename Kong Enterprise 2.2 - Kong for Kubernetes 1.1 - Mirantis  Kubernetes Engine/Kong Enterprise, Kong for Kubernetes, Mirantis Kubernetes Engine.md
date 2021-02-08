
Mirantis Container Runtime (MCR) Installation
https://docs.mirantis.com/docker-enterprise/v3.1/

https://docs.mirantis.com/docker-enterprise/v3.1/dockeree-products/mcr.html

The product formerly known as Docker Engine - Enterprise is now Mirantis Container Runtime (MCR).

Go to EC2 dashboard and click on "Launch Instance". Select "Ubuntu Server 18.04 LTS (HVM), and "t2.xlarge" Instance Type and 50GB of storage.

<pre>
ssh -i "claudio-acquaviva.pem" ubuntu@ec2-34-220-139-185.us-west-2.compute.amazonaws.com
</pre>

Install utilities
<pre>
sudo apt-get -y update
sudo apt -y install httpie jq 

sudo apt-get -y install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common
</pre>

Install Mirantis Container Runtime
<pre>
export DOCKER_EE_URL="https://repos.mirantis.com"
export DOCKER_EE_VERSION=19.03

curl -fsSL "${DOCKER_EE_URL}/ubuntu/gpg" | sudo apt-key add -

sudo apt-key fingerprint 6D085F96

sudo add-apt-repository \
   "deb [arch=$(dpkg --print-architecture)] $DOCKER_EE_URL/ubuntu \
   $(lsb_release -cs) \
   stable-$DOCKER_EE_VERSION"

sudo apt-get update

sudo apt-get install docker-ee docker-ee-cli containerd.io -y

sudo docker run hello-world

sudo systemctl enable docker.service
sudo systemctl start docker.service
sudo systemctl stop docker.service
</pre>

Check the installation with:
<pre>
$ sudo docker info
Client:
 Debug Mode: false
 Plugins:
  cluster: Manage Mirantis Container Cloud clusters (Mirantis Inc., v1.9.0)
  containercloud: Manage Docker Enterprise Container Cloud (Mirantis Inc., v0.1.0-beta1)

Server:
 Containers: 1
  Running: 0
  Paused: 0
  Stopped: 1
 Images: 1
 Server Version: 19.03.14
 Storage Driver: overlay2
  Backing Filesystem: extfs
  Supports d_type: true
  Native Overlay Diff: true
 Logging Driver: json-file
 Cgroup Driver: cgroupfs
 Plugins:
  Volume: local
  Network: bridge host ipvlan macvlan null overlay
  Log: awslogs fluentd gcplogs gelf journald json-file local logentries splunk syslog
 Swarm: inactive
 Runtimes: runc
 Default Runtime: runc
 Init Binary: docker-init
 containerd version: ea765aba0d05254012b0b9e595e995c09186427f
 runc version: dc9208a3303feef5b3839f4323d9beb36df0a9dd
 init version: fec3683
 Security Options:
  apparmor
  seccomp
   Profile: default
 Kernel Version: 5.4.0-1029-aws
 Operating System: Ubuntu 18.04.5 LTS
 OSType: linux
 Architecture: x86_64
 CPUs: 2
 Total Memory: 7.773GiB
 Name: ip-172-31-12-222
 ID: JOWK:IMRZ:VS5V:DFSC:4ET5:3T4Z:6J5K:PDVB:NUOF:YBSJ:PQ4V:MSWP
 Docker Root Dir: /var/lib/docker
 Debug Mode: false
 Registry: https://index.docker.io/v1/
 Labels:
  com.docker.security.apparmor=enabled
  com.docker.security.seccomp=enabled
 Experimental: false
 Insecure Registries:
  127.0.0.0/8
 Live Restore Enabled: false
 Product License: this node is not a swarm manager - check license status on a manager node

WARNING: No swap limit support
</pre>


Portainer installation
sudo docker volume create portainer_data

sudo docker run --name portainer -d -p 9000:9000 -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer

sudo docker start portainer

Using the EC2's public address, check the installation:
http://34.220.139.185:9000

At the first access, Portainer asks to define the admin's password. Choose "portainer".

After choosing the "Local - Manage the local Docker environment", we'll see its home page.


Mirantis Kubernetes Engine (MKE) Installation
https://docs.mirantis.com/docker-enterprise/v3.1/dockeree-products/mke.html


UCP is now MKE: The product formerly known as Docker Enterprise is now Mirantis Kubernetes Engine (MKE).


MKE installation
sudo docker image pull mirantis/ucp:3.3.5

sudo docker container run --rm -it --name ucp \
  -v /var/run/docker.sock:/var/run/docker.sock \
  mirantis/ucp:3.3.5 install \
  --host-address 172.31.5.42 \
  --interactive

Obs.:
172.31.5.42 is the EC2's Private IP
Use "admin" and "kubernetes" as the uid and password
Include EC2's Public IP (34.220.139.185) for "Additional aliases"

Output:
INFO[0000] Your Docker daemon version 19.03.14, build 57e3a05 (5.4.0-1029-aws) is compatible with UCP 3.3.5 (da5c8e9) 
INFO[0000] Initializing New Docker Swarm                
Admin Username: admin
Admin Password: 
Confirm Admin Password: 
WARN[0016] None of the Subject Alternative Names we'll be using in the UCP certificates ["ip-172-31-5-42"] contain a domain component. Your generated certs may fail TLS validation unless you only use one of these shortnames or IP addresses to connect. You can use the --san flag to add more aliases 

You may enter additional aliases (SANs) now or press enter to proceed with the above list.
Additional aliases: 34.220.139.185
INFO[0024] Checking required ports for connectivity     
INFO[0029] Checking required container images           
INFO[0029] Pulling required images... (this may take a while) 
INFO[0029] Pulling image: mirantis/ucp-agent:3.3.5      
INFO[0031] Pulling image: mirantis/ucp-auth:3.3.5       
INFO[0035] Pulling image: mirantis/ucp-auth-store:3.3.5 
INFO[0039] Pulling image: mirantis/ucp-azure-ip-allocator:3.3.5 
INFO[0042] Pulling image: mirantis/ucp-calico-cni:3.3.5 
INFO[0046] Pulling image: mirantis/ucp-calico-kube-controllers:3.3.5 
INFO[0048] Pulling image: mirantis/ucp-calico-node:3.3.5 
INFO[0053] Pulling image: mirantis/ucp-cfssl:3.3.5      
INFO[0054] Pulling image: mirantis/ucp-compose:3.3.5    
INFO[0061] Pulling image: mirantis/ucp-containerd-shim-process:3.3.5 
INFO[0062] Pulling image: mirantis/ucp-controller:3.3.5 
INFO[0066] Pulling image: mirantis/ucp-dsinfo:3.3.5     
INFO[0067] Pulling image: mirantis/ucp-etcd:3.3.5       
INFO[0070] Pulling image: mirantis/ucp-hyperkube:3.3.5  
INFO[0076] Pulling image: mirantis/ucp-interlock:3.3.5  
INFO[0078] Pulling image: mirantis/ucp-interlock-extension:3.3.5 
INFO[0081] Pulling image: mirantis/ucp-interlock-proxy:3.3.5 
INFO[0085] Pulling image: mirantis/ucp-interlock-config:3.3.5 
INFO[0087] Pulling image: mirantis/ucp-kube-compose:3.3.5 
INFO[0089] Pulling image: mirantis/ucp-kube-compose-api:3.3.5 
INFO[0093] Pulling image: mirantis/ucp-kube-gmsa-webhook:3.3.5 
INFO[0096] Pulling image: mirantis/ucp-coredns:3.3.5    
INFO[0098] Pulling image: mirantis/ucp-metrics:3.3.5    
INFO[0101] Pulling image: mirantis/ucp-pause:3.3.5      
INFO[0102] Pulling image: mirantis/ucp-swarm:3.3.5      
INFO[0103] Pulling image: mirantis/ucp-istio-node-agent-k8s:3.3.5 
INFO[0110] Pulling image: mirantis/ucp-istio-pilot:3.3.5 
INFO[0112] Pulling image: mirantis/ucp-istio-proxyv2:3.3.5 
INFO[0116] Pulling image: mirantis/ucp-istio-mixer:3.3.5 
INFO[0118] Pulling image: mirantis/ucp-openstack-ccm:3.3.5 
INFO[0122] Pulling image: mirantis/ucp-openstack-cinder-csi-plugin:3.3.5 
INFO[0125] Pulling image: mirantis/ucp-csi-attacher:3.3.5 
INFO[0127] Pulling image: mirantis/ucp-csi-provisioner:3.3.5 
INFO[0130] Pulling image: mirantis/ucp-csi-snapshotter:3.3.5 
INFO[0134] Pulling image: mirantis/ucp-csi-resizer:3.3.5 
INFO[0136] Pulling image: mirantis/ucp-csi-node-driver-registrar:3.3.5 
INFO[0138] Pulling image: mirantis/ucp-csi-liveness-probe:3.3.5 
INFO[0140] Completed pulling required images            
WARN[0140] Possible conflict between Kubernetes pod CIDR range 192.168.0.0/16 and default address pool for Docker Engine interface and bridge networks 192.168.0.0/16 
WARN[0140] Possible conflict between Kubernetes service CIDR range 10.96.0.0/16 and default address pool for Swarm overlay networks 10.0.0.0/8 
INFO[0140] disabling checks which rely on detecting which (if any) cloud provider the cluster is currently running on 
INFO[0140] Running install agent container ...          
INFO[0000] Loading install configuration                
INFO[0000] Running Installation Steps                   
INFO[0000] Step 1 of 39: [Setup Internal Cluster CA]    
INFO[0003] Step 2 of 39: [Setup Internal Client CA]     
INFO[0003] Step 3 of 39: [Initialize etcd Cluster]      
INFO[0005] Step 4 of 39: [Set Initial Config in etcd]   
INFO[0005] Step 5 of 39: [Deploy RethinkDB Server]      
INFO[0007] Step 6 of 39: [Initialize RethinkDB Tables]  
INFO[0011] Step 7 of 39: [Create Auth Service Encryption Key Secret] 
INFO[0011] Step 8 of 39: [Deploy Auth API Server]       
INFO[0014] Step 9 of 39: [Setup Auth Configuration]     
INFO[0015] Step 10 of 39: [Deploy Auth Worker Server]   
INFO[0016] Step 11 of 39: [Deploy MKE Proxy Server]     
INFO[0017] Step 12 of 39: [Initialize Swarm v1 Node Inventory] 
INFO[0017] Step 13 of 39: [Deploy Swarm v1 Manager Server] 
INFO[0018] Step 14 of 39: [Deploy Internal Cluster CA Server] 
INFO[0019] Step 15 of 39: [Deploy Internal Client CA Server] 
INFO[0020] Step 16 of 39: [Deploy MKE Controller Server] 
INFO[0024] Step 17 of 39: [Deploy Kubernetes API Server] 
INFO[0032] Step 18 of 39: [Deploy Kubernetes Controller Manager] 
INFO[0036] Step 19 of 39: [Deploy Kubernetes Scheduler] 
INFO[0040] Step 20 of 39: [Deploy Kubelet]              
INFO[0065] Step 21 of 39: [Deploy Kubernetes Proxy]     
INFO[0065] Step 22 of 39: [Wait for Healthy MKE Controller and Kubernetes API] 
INFO[0069] Step 23 of 39: [Create Kubernetes Pod Security Policies] 
INFO[0070] Step 24 of 39: [Install default storage class based on cloudprovider (for deprecated InTree providers)] 
INFO[0070] Step 25 of 39: [Install Kubernetes CNI Plugin] 
INFO[0088] Step 26 of 39: [Install CoreDNS]             
INFO[0090] Step 27 of 39: [Install Cloud Controller Manager based on cloudprovider] 
INFO[0090] Step 28 of 39: [Install Container Storage Interface Driver based on cloudprovider] 
INFO[0090] Step 29 of 39: [Install Istio Ingress]       
INFO[0101] Step 30 of 39: [Create MKE Controller Kubernetes Service Endpoints] 
INFO[0102] Step 31 of 39: [Install Metrics Plugin]      
INFO[0104] Step 32 of 39: [Install Kubernetes Compose Plugin] 
INFO[0109] Step 33 of 39: [Deploy Manager Node Agent Service] 
INFO[0109] Step 34 of 39: [Deploy Worker Node Agent Service] 
INFO[0109] Step 35 of 39: [Deploy Windows Worker Node Agent Service] 
INFO[0109] Step 36 of 39: [Deploy Cluster Agent Service] 
INFO[0109] Step 37 of 39: [Set License]                 
INFO[0109] Step 38 of 39: [Set Registry CA Certificates] 
INFO[0109] Step 39 of 39: [Wait for All Nodes to be Ready] 
INFO[0114] All Installation Steps Completed  



If you want to uninstall it:

sudo docker container run --rm -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --name ucp \
  mirantis/ucp:3.3.5 uninstall-ucp --interactive







Mirantis Kubernetes Engine Web UI
Redirect your browser to https://34.220.139.185. Use the admin/pwd you defined during installation to login.


Upload the trial license to go to the landing page:



Mirantis Secure Registry (MSR)
https://docs.mirantis.com/docker-enterprise/v3.1/dockeree-products/msr.html

The product formerly known as Docker Trusted Registry (DTR) is now Mirantis Secure Registry (MSR).

Create another EC2 instance to install MSR). Kong Enterprise images copied from Bintray repositories will be stored here.

Go to EC2 dashboard and click on "Launch Instance". Select "Ubuntu Server 18.04 LTS (HVM), and "t2.xlarge" Instance Type and 50GB of storage.

ssh -i "claudio-acquaviva.pem" ubuntu@ec2-34-222-221-3.us-west-2.compute.amazonaws.com


Install utilities
sudo apt-get -y update
sudo apt -y install httpie jq

sudo apt-get -y install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common


Install Mirantis Container Runtime
export DOCKER_EE_URL="https://repos.mirantis.com"
export DOCKER_EE_VERSION=19.03

curl -fsSL "${DOCKER_EE_URL}/ubuntu/gpg" | sudo apt-key add -

sudo apt-key fingerprint 6D085F96

sudo add-apt-repository \
   "deb [arch=$(dpkg --print-architecture)] $DOCKER_EE_URL/ubuntu \
   $(lsb_release -cs) \
   stable-$DOCKER_EE_VERSION"

sudo apt-get update

sudo apt-get install docker-ee docker-ee-cli containerd.io -y

sudo docker run hello-world

sudo systemctl enable docker.service
sudo systemctl start docker.service
sudo systemctl stop docker.service

Check the installation with:
$ sudo docker info
Client:
 Debug Mode: false
 Plugins:
  cluster: Manage Mirantis Container Cloud clusters (Mirantis Inc., v1.9.0)
  containercloud: Manage Docker Enterprise Container Cloud (Mirantis Inc., v0.1.0-beta1)

Server:
 Containers: 1
  Running: 0
  Paused: 0
  Stopped: 1
 Images: 1
 Server Version: 19.03.14
 Storage Driver: overlay2
  Backing Filesystem: extfs
  Supports d_type: true
  Native Overlay Diff: true
 Logging Driver: json-file
 Cgroup Driver: cgroupfs
 Plugins:
  Volume: local
  Network: bridge host ipvlan macvlan null overlay
  Log: awslogs fluentd gcplogs gelf journald json-file local logentries splunk syslog
 Swarm: inactive
 Runtimes: runc
 Default Runtime: runc
 Init Binary: docker-init
 containerd version: ea765aba0d05254012b0b9e595e995c09186427f
 runc version: dc9208a3303feef5b3839f4323d9beb36df0a9dd
 init version: fec3683
 Security Options:
  apparmor
  seccomp
   Profile: default
 Kernel Version: 5.4.0-1029-aws
 Operating System: Ubuntu 18.04.5 LTS
 OSType: linux
 Architecture: x86_64
 CPUs: 4
 Total Memory: 15.64GiB
 Name: ip-172-31-4-95
 ID: D6L5:FNGX:KIE2:LCV5:PPP2:YUM7:7SJO:Y2FQ:YO7E:VXBW:WHTE:WT5R
 Docker Root Dir: /var/lib/docker
 Debug Mode: false
 Registry: https://index.docker.io/v1/
 Labels:
  com.docker.security.apparmor=enabled
  com.docker.security.seccomp=enabled
 Experimental: false
 Insecure Registries:
  127.0.0.0/8
 Live Restore Enabled: false
 Product License: this node is not a swarm manager - check license status on a manager node

WARNING: No swap limit support


Portainer installation
sudo docker volume create portainer_data

sudo docker run --name portainer -d -p 9000:9000 -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer

sudo docker start portainer

Using the EC2's public address, check the installation:
http://34.222.221.3:9000

At the first access, Portainer asks to define the admin's password. Choose "portainer".

After choosing the "Local - Manage the local Docker environment", we'll see its home page.


Connection testing
Using Private and Public IPs, ping MSR from MKE

ping 34.222.221.3
ping 172.31.13.110


Using Private IP, ping MKE from MSR

ping 34.220.139.185
ping 172.31.5.42


Add MSR to MKE
On MKE run:

$ sudo docker swarm join-token worker
To add a worker to this swarm, run the following command:

    docker swarm join --token SWMTKN-1-5u33sgghgxa5znh9vef9k25kbh8wtk5f8di21bi5la71zxgq9l-dg3j5hhnc4jwmdgi7t5dy4261 172.31.5.42:2377


Copy the command output, go to MSR and run it:

$ sudo docker swarm join --token SWMTKN-1-24qwditl5ndg5378lwd0uk0q4db2im20rc5mi5yrhpo5el6sil-6sy2modce3csukwbmw7qyual7 172.31.3.139:2377
This node joined a swarm as a worker.


Go back to MKE and run:
$ sudo docker node ls
ID                            HOSTNAME            STATUS              AVAILABILITY        MANAGER STATUS      ENGINE VERSION
ugykdu36o2uysi8b6gpklkbwf *   ip-172-31-5-42      Ready               Active              Leader              19.03.14
b9226n0jcd73dqm2a537ob0rb     ip-172-31-13-110    Ready               Active                                  19.03.14








Mirantis Secure Registry installation
Run the following command from MKE, not MSR. Use "admin" and "kubernetes" as the uid and password, as specified during MKE installation.

dtr-external-url is the MSR's Public IP.
ucp-node is the MSR's worker node name.
ucp-url is the MKE's Public IP.

sudo docker run -it --rm docker/dtr:latest install --dtr-external-url https://34.222.221.3 --ucp-node ip-172-31-13-110 --ucp-url https://34.220.139.185 --ucp-insecure-tls



Output:
$ sudo docker run -it --rm docker/dtr:latest install --dtr-external-url https://34.222.221.3 --ucp-node ip-172-31-13-110 --ucp-url https://34.220.139.185 --ucp-insecure-tls
Unable to find image 'docker/dtr:latest' locally
latest: Pulling from docker/dtr
89d9c30c1d48: Pull complete 
b5dbeef76e97: Pull complete 
a05203c8d881: Pull complete 
07a26892d619: Pull complete 
c33fda54fc88: Pull complete 
Digest: sha256:39ca86111a13b97a1fe89e9dca6303cc19d5b306966886fefbac058425ba1356
Status: Downloaded newer image for docker/dtr:latest
INFO[0000] Beginning Docker Trusted Registry installation 
ucp-username (The UCP administrator username): admin
ucp-password: 
INFO[0028] Validating UCP cert                          
INFO[0028] Connecting to UCP                            
INFO[0028] health checking ucp                          
INFO[0028] Only one available UCP node detected. Picking UCP node 'ip-172-31-13-110' 
INFO[0028] Searching containers in UCP for DTR replicas 
INFO[0028] Searching containers in UCP for DTR replicas 
INFO[0028] verifying [80 443] ports on ip-172-31-13-110 
INFO[0037] Waiting for running dtr-phase2 container to finish 
INFO[0037] starting phase 2                             
INFO[0000] Validating UCP cert                          
INFO[0000] Connecting to UCP                            
INFO[0000] health checking ucp                          
INFO[0000] Verifying your system is compatible with DTR 
INFO[0000] Checking if the node is okay to install on   
INFO[0000] Using default overlay subnet: 10.1.0.0/24    
INFO[0000] Creating network: dtr-ol                     
INFO[0000] Connecting to network: dtr-ol                
INFO[0000] Waiting for phase2 container to be known to the Docker daemon 
INFO[0001] Setting up replica volumes...                
INFO[0001] Creating initial CA certificates             
INFO[0001] Bootstrapping rethink...                     
INFO[0002] Creating dtr-rethinkdb-3f14cdadc652...       
INFO[0011] Establishing connection with Rethinkdb       
INFO[0012] Waiting for database dtr2 to exist           
INFO[0012] Waiting for database dtr2 to exist           
INFO[0012] Waiting for database dtr2 to exist           
INFO[0012] Generated TLS certificate.                    dnsNames="[]" domains="[34.222.221.3]" ipAddresses="[34.222.221.3]"
INFO[0013] License config copied from UCP.              
INFO[0013] Migrating db...                              
INFO[0000] Establishing connection with Rethinkdb       
INFO[0000] Migrating database schema                     fromVersion=0 toVersion=10
INFO[0002] Waiting for database notaryserver to exist   
INFO[0002] Waiting for database notaryserver to exist   
INFO[0002] Waiting for database notaryserver to exist   
INFO[0003] Waiting for database notarysigner to exist   
INFO[0003] Waiting for database notarysigner to exist   
INFO[0004] Waiting for database notarysigner to exist   
INFO[0004] Waiting for database jobrunner to exist      
INFO[0004] Waiting for database jobrunner to exist      
INFO[0005] Waiting for database jobrunner to exist      
INFO[0006] Migrating database schema                     fromVersion=10 toVersion=11
INFO[0006] Migrated database from version 0 to 11       
INFO[0019] Starting all containers...                   
INFO[0019] Getting container configuration and starting containers... 
INFO[0019] Automatically configuring rethinkdb cache size to 5802 mb 
INFO[0020] Recreating dtr-rethinkdb-3f14cdadc652...     
INFO[0027] Creating dtr-registry-3f14cdadc652...        
INFO[0036] Creating dtr-garant-3f14cdadc652...          
INFO[0045] Creating dtr-api-3f14cdadc652...             
INFO[0075] Creating dtr-notary-server-3f14cdadc652...   
INFO[0084] Recreating dtr-nginx-3f14cdadc652...         
INFO[0095] Creating dtr-jobrunner-3f14cdadc652...       
INFO[0105] Creating dtr-notary-signer-3f14cdadc652...   
INFO[0112] Creating dtr-scanningstore-3f14cdadc652...   
INFO[0122] Trying to get the kv store connection back after reconfigure 
INFO[0122] Establishing connection with Rethinkdb       
INFO[0122] Verifying auth settings...                   
INFO[0122] Successfully registered DTR with UCP         
INFO[0122] Installation is complete                     
INFO[0122] Replica ID is set to: 3f14cdadc652           
INFO[0122] You can use flag '--existing-replica-id 3f14cdadc652' when joining other replicas to your Docker Trusted Registry Cluster 


If you want to uninstall it:

sudo docker run -it --rm mirantis/dtr:lastest destroy --ucp-insecure-tls
//sudo docker run -it --rm mirantis/dtr destroy --ucp-url https://54.188.84.2 --ucp-insecure-tls

Go to MKE console



Private Repository setting
Go to MSR using its EC2's Public IP. Accept the Digital Certificate presented by the Server. Since we've got SSO between MSR and MKE, we get redirected to Repositories page.



Kong Enterprise Docker Images
Register MSR as an insecure-registry
For lab purposes, let's register MSR as an insecure register. Using Docker Desktop 3.1.0 on a MacOS, click on Docker->Preferences


Click on "Docker Engine" and include the MSR's Public IP address as an insecure registry:


Click on  "Apply & Restart" button.



Kong Enterprise and Mirantis Secure Registry
Click on "Repositories" .-> "New Repository". Create a "kong-enterprise-edition" and a "postgres" repository.






Push Kong Enterprise to MSR
From a local terminal, login to Kong Bintray

docker login -u cacquaviva -p <API-KEY> kong-docker-kong-enterprise-edition-docker.bintray.io

Pull Kong Enterprise and PostgreSQL image from public repositories

docker pull kong-docker-kong-enterprise-edition-docker.bintray.io/kong-enterprise-edition:2.2.1.0-alpine

docker pull postgres:latest

Tag the images using MSR's Public IP

docker tag kong-docker-kong-enterprise-edition-docker.bintray.io/kong-enterprise-edition:2.2.1.0-alpine 34.222.221.3/admin/kong-enterprise-edition:2.2.1.0-alpine

docker tag postgres:latest 34.222.221.3/admin/postgres:latest



Login to MSR

$ docker login 34.222.221.3
Username: admin
Password: 
Login Succeeded


Push Kong Enterprise Image

docker image push 34.222.221.3/admin/kong-enterprise-edition:2.2.1.0-alpine

docker image push 34.222.221.3/admin/postgres:latest

Check the Images:





Delete the local images:

docker image rm kong-docker-kong-enterprise-edition-docker.bintray.io/kong-enterprise-edition:2.2.1.0-alpine
docker image rm 34.222.221.3/admin/kong-enterprise-edition:2.2.1.0-alpine

docker image rm postgres:latest
docker image rm 34.222.221.3/admin/postgres:latest


Kong Enterprise installation - CLI
Still on MacOS run:

Check your local images

$ docker image ls
REPOSITORY            TAG                 IMAGE ID            CREATED             SIZE


Login to MSR
$ docker login 34.222.221.3
Username: admin
Password: 
Login Succeeded


Pull Kong Enterprise image from MSR
docker pull 34.222.221.3/admin/kong-enterprise-edition:2.2.1.0-alpine


Tag the local image
docker tag 34.222.221.3/admin/kong-enterprise-edition:2.2.1.0-alpine kong-ee


Create a PostgreSQL container
docker run -d --name kong-ee-database \
   -p 5432:5432 \
   -e "POSTGRES_USER=kong" \
   -e "POSTGRES_DB=kong" \
   -e "POSTGRES_HOST_AUTH_METHOD=trust" \
   34.222.221.3/admin/postgres:latest


Define the KONG_LICENSE_DATA env variable
export KONG_LICENSE_DATA='{"license":{"signature":"xxxxxx","payload":{"customer":"Kong_SE_Demo","license_creation_date":"2019-11-03","product_subscription":"Kong Enterprise Edition","admin_seats":"5","support_plan":"None","license_expiration_date":"2020-12-12","license_key":"yyyyyy"},"version":1}}'


Create a Docker network
docker network create kong-net


Bootstrap the PostgreSQL database:
docker run --rm --link kong-ee-database:kong-ee-database \
   -e "KONG_DATABASE=postgres" -e "KONG_PG_HOST=kong-ee-database" \
   -e "KONG_LICENSE_DATA=$KONG_LICENSE_DATA" \
   -e "KONG_PASSWORD=kong" \
   -e "POSTGRES_PASSWORD=kong" \
   kong-ee kong migrations bootstrap


Start the Kong Enterprise container:
docker run -d --name kong-ee --link kong-ee-database:kong-ee-database \
  -e "KONG_DATABASE=postgres" \
  -e "KONG_PG_HOST=kong-ee-database" \
  -e "KONG_PROXY_ACCESS_LOG=/dev/stdout" \
  -e "KONG_ADMIN_ACCESS_LOG=/dev/stdout" \
  -e "KONG_PORTAL_API_ACCESS_LOG=/dev/stdout" \
  -e "KONG_PROXY_ERROR_LOG=/dev/stderr" \
  -e "KONG_PORTAL_API_ERROR_LOG=/dev/stderr" \
  -e "KONG_ADMIN_ERROR_LOG=/dev/stderr" \
  -e "KONG_ADMIN_LISTEN=0.0.0.0:8001, 0.0.0.0:8444 ssl" \
  -e "KONG_ADMIN_GUI_LISTEN=0.0.0.0:8002, 0.0.0.0:8445 ssl" \
  -e "KONG_PORTAL=on" \
  -e "KONG_PORTAL_GUI_PROTOCOL=http" \
  -e "KONG_PORTAL_GUI_HOST=localhost:8003" \
  -e "KONG_PORTAL_SESSION_CONF={\"cookie_name\": \"portal_session\", \"secret\": \"portal_secret\", \"storage\":\"kong\", \"cookie_secure\": false}" \
  -e "KONG_LICENSE_DATA=$KONG_LICENSE_DATA" \
  -p 8000:8000 \
  -p 8443:8443 \
  -p 8001:8001 \
  -p 8444:8444 \
  -p 8002:8002 \
  -p 8445:8445 \
  -p 8003:8003 \
  -p 8446:8446 \
  -p 8004:8004 \
  -p 8447:8447 \
  kong-ee


Test the installation
http patch :8001/workspaces/default config:='{"portal": true}'

docker network connect kong-net kong-ee
docker network connect kong-net kong-ee-database

http --verify=no https://localhost:8443
http --verify=no https://localhost:8444

docker stop kong-ee
docker stop kong-ee-database

docker start kong-ee-database
docker start kong-ee

$ http :8001 | jq .version
"2.2.1.0-enterprise-edition"






Kong Enterprise installation - Docker Compose
Create Kong Enterprise Docker Compose file
Below is an example of a docker-compose.yml file. Notice the KONG_PORTAL_GUI_HOST configuration is pointing to the MKE's public address, 34.220.139.185

version: "3.1"

services:

 postgres:
  image: 34.222.221.3/admin/postgres:latest
  container_name: postgres
  ports:
   - 5432:5432
  environment:
   - POSTGRES_USER=kong
   - POSTGRES_DB=kong
   - POSTGRES_HOST_AUTH_METHOD=trust

 kong-ent-bootstrap:
  image: 34.222.221.3/admin/kong-enterprise-edition:2.2.1.0-alpine
  container_name: kong-ent-bootstrap
  hostname: kongBootstrap
  depends_on:
   - postgres
  restart: on-failure
  command: "kong migrations bootstrap"
  environment:
   - KONG_LICENSE_DATA={"license":{"version":1,"signature":"xxxxx","payload":{"customer":"Kong_SE_Demo_H1FY22","license_creation_date":"2020-11-30","product_subscription":"Kong Enterprise Edition","support_plan":"None","admin_seats":"5","dataplanes":"5","license_expiration_date":"2021-06-30","license_key":"yyyyy"}}}
   - KONG_DATABASE=postgres
   - KONG_PG_HOST=postgres

 kong-ee:
  image: 34.222.221.3/admin/kong-enterprise-edition:2.2.1.0-alpine
  container_name: kong-ee
  hostname: kong-ee
  depends_on:
   - postgres
   - kong-ent-bootstrap
  ports:
   - 8000:8000
   - 8001:8001
   - 8002:8002
   - 8003:8003
   - 8004:8004
   - 8443:8443
   - 8444:8444
   - 8445:8445
   - 8446:8446
   - 8447:8447
  environment:
   - KONG_DATABASE=postgres
   - KONG_PG_HOST=postgres
   - KONG_PROXY_ACCESS_LOG=/dev/stdout
   - KONG_ADMIN_ACCESS_LOG=/dev/stdout
   - KONG_PORTAL_ACCESS_LOG=/dev/stdout
   - KONG_PROXY_ERROR_LOG=/dev/stderr
   - KONG_ADMIN_ERROR_LOG=/dev/stderr
   - KONG_PORTAL_ERROR_LOG=/dev/stderr
   - KONG_ADMIN_LISTEN=0.0.0.0:8001, 0.0.0.0:8444 ssl
   - KONG_ADMIN_GUI_LISTEN=0.0.0.0:8002, 0.0.0.0:8445 ssl
   - KONG_PORTAL=on
   - KONG_PORTAL_GUI_PROTOCOL=http
   - KONG_PORTAL_GUI_HOST=54.188.84.2:8003
   - KONG_PORTAL_SESSION_CONF={"storage":"kong","cookie_name":"portal_session","secret":"super-secret","cookie_secure":false}
   - KONG_LICENSE_DATA={"license":{"version":1,"signature":"xxxxx","payload":{"customer":"Kong_SE_Demo_H1FY22","license_creation_date":"2020-11-30","product_subscription":"Kong Enterprise Edition","support_plan":"None","admin_seats":"5","dataplanes":"5","license_expiration_date":"2021-06-30","license_key":"yyyyy"}}}


Create Kong Enterprise Docker Compose Stack
From MKE, on the left menu bar click on "Shared Resources" -> "Stacks" and "Create Stack".
For Name, type "kong". Click on "Next".
Click on "Upload docker-compose.yml file" link and upload the docker-compose.yml described above.


Click on "Create". Wait for deployment and click on "Done"


Check Kong Enterprise deployment
Open a terminal on MKE and run:

$ http :8001 | jq .version
"2.2.1.0-enterprise-edition"





Redirect you browser to http://<MKE's public IP>:8002


Delete Kong Enterprise deployment
If you want to delete the Stack click on the right menu:





Kong Enterprise Service, Route and Plugins
Create a Service
Go to Kong Manager and click on "Workspace" default. Click on "Services"


Click on "New Service" and define a "httpbinservice" Service with the "http://httpbin.org" URL:


Click on "Create":


Create a Route
Click on "Add Route"


Type "httpbinroute" for Name. Click on "Add Path" and type "/httpbin".


Click on "Create"




Consume the Route
$ http :8000/httpbin/get
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: *
Connection: keep-alive
Content-Length: 423
Content-Type: application/json
Date: Mon, 18 Jan 2021 21:24:06 GMT
Server: gunicorn/19.9.0
Via: kong/2.2.1.0-enterprise-edition
X-Kong-Proxy-Latency: 89
X-Kong-Upstream-Latency: 147

{
    "args": {},
    "headers": {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Host": "httpbin.org",
        "User-Agent": "HTTPie/0.9.8",
        "X-Amzn-Trace-Id": "Root=1-6005fc76-1ef4b6971324332a1637e191",
        "X-Forwarded-Host": "localhost",
        "X-Forwarded-Path": "/httpbin/get",
        "X-Forwarded-Prefix": "/httpbin"
    },
    "origin": "10.0.0.2, 34.220.139.185",
    "url": "http://localhost/get"
}



Apply the Rate Limiting Plugin to the Route
Go back to the "httpbinroute" Route page and click on "Add a Plugin".


Click on "Rate Limiting" plugin. Set the "Config.Minute" parameter with 3.


Click on "Create"


Consume the Route again
Notice that, this time, we get specific Rate Limiting headers.

$ http :8000/httpbin/get
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: *
Connection: keep-alive
Content-Length: 423
Content-Type: application/json
Date: Mon, 18 Jan 2021 21:28:20 GMT
RateLimit-Limit: 3
RateLimit-Remaining: 2
RateLimit-Reset: 40
Server: gunicorn/19.9.0
Via: kong/2.2.1.0-enterprise-edition
X-Kong-Proxy-Latency: 40
X-Kong-Upstream-Latency: 130
X-RateLimit-Limit-Minute: 3
X-RateLimit-Remaining-Minute: 2

{
    "args": {},
    "headers": {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Host": "httpbin.org",
        "User-Agent": "HTTPie/0.9.8",
        "X-Amzn-Trace-Id": "Root=1-6005fd74-1414deb86253203871a78ca0",
        "X-Forwarded-Host": "localhost",
        "X-Forwarded-Path": "/httpbin/get",
        "X-Forwarded-Prefix": "/httpbin"
    },
    "origin": "10.0.0.2, 34.220.139.185",
    "url": "http://localhost/get"
}


If we keep sending requests to the Gateway we're going to get a 429 error code:

$ http :8000/httpbin/get
HTTP/1.1 429 Too Many Requests
Connection: keep-alive
Content-Length: 41
Content-Type: application/json; charset=utf-8
Date: Mon, 18 Jan 2021 21:28:26 GMT
RateLimit-Limit: 3
RateLimit-Remaining: 0
RateLimit-Reset: 34
Retry-After: 34
Server: kong/2.2.1.0-enterprise-edition
X-Kong-Response-Latency: 3
X-RateLimit-Limit-Minute: 3
X-RateLimit-Remaining-Minute: 0

{
    "message": "API rate limit exceeded"
}

Kong for Kubernetes Ingress Controller
We are going to install and test Kong for Kubernetes (K4K8S) from MKE host.

Install kubectl on MKE host
curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"

chmod +x ./kubectl

./kubectl version


Install Helm on MKE host
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3

$ chmod 700 get_helm.sh
$ ./get_helm.sh
helm version

Download MKE Client Bundle
mkdir mirantis
cd mirantis

# Create an environment variable with the user security token
AUTHTOKEN=$(curl -sk -d '{"username":"admin","password":"kubernetes"}' https://34.220.139.185/auth/login | jq -r .auth_token)

# Download the client certificate bundle
curl -k -H "Authorization: Bearer $AUTHTOKEN" https://34.220.139.185/api/clientbundle -o bundle.zip

# Unzip the bundle.
unzip bundle.zip

# Run the utility script.
eval "$(<env.sh)"


Testing the connection
Test if you can connect to Kubernetes Cluster using:
$ kubectl config get-contexts
CURRENT   NAME                            CLUSTER                         AUTHINFO                        NAMESPACE
*         ucp_34.220.139.185:6443_admin   ucp_34.220.139.185:6443_admin   ucp_34.220.139.185:6443_admin   


$ kubectl get pod --all-namespaces
NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE
kube-system   calico-kube-controllers-784d968c7f-lw8t8   1/1     Running   0          3h30m
kube-system   calico-node-lgscz                          2/2     Running   0          3h30m
kube-system   calico-node-mc8b8                          2/2     Running   0          118m
kube-system   compose-api-fc595464f-rt56n                1/1     Running   0          3h29m
kube-system   compose-c78b96dc8-xvnlj                    1/1     Running   0          3h29m
kube-system   coredns-665c6f959f-p49ss                   1/1     Running   0          3h29m
kube-system   coredns-665c6f959f-sr56w                   1/1     Running   0          3h29m
kube-system   ucp-metrics-f2vz6                          3/3     Running   1          3h29m
kube-system   ucp-nvidia-device-plugin-cwrpg             1/1     Running   0          3h29m
kube-system   ucp-nvidia-device-plugin-mbl74             1/1     Running   0          118m


Install Kong for Kubernetes
$ helm repo add kong https://charts.konghq.com
"kong" has been added to your repositories

$ helm repo update
Hang tight while we grab the latest from your chart repositories...
...Successfully got an update from the "kong-mesh" chart repository
...Successfully got an update from the "kong" chart repository
Update Complete. ⎈Happy Helming!⎈

$ helm repo ls
NAME     	URL                                    
kong     	https://charts.konghq.com              

$ kubectl create namespace kong
namespace/kong created

For the lab only, we're going to deploy Kong for Kubernetes using NodePort type. For production environments, we usually deploy it as LoadBalancer:

$ helm install kong -n kong kong/kong \
    --set ingressController.installCRDs=false \
    --set proxy.type=NodePort \
    --set proxy.http.nodePort=32780


Check the installation
$ kubectl get pod --all-namespaces
NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE
kong          kong-kong-75467bff7f-5z4ll                 2/2     Running   0          9m46s
kube-system   calico-kube-controllers-784d968c7f-lw8t8   1/1     Running   0          5h26m
kube-system   calico-node-lgscz                          2/2     Running   0          5h26m
kube-system   calico-node-mc8b8                          2/2     Running   0          3h55m
kube-system   compose-api-fc595464f-rt56n                1/1     Running   0          5h26m
kube-system   compose-c78b96dc8-xvnlj                    1/1     Running   0          5h26m
kube-system   coredns-665c6f959f-p49ss                   1/1     Running   0          5h26m
kube-system   coredns-665c6f959f-sr56w                   1/1     Running   0          5h26m
kube-system   ucp-metrics-f2vz6                          3/3     Running   1          5h26m
kube-system   ucp-nvidia-device-plugin-cwrpg             1/1     Running   0          5h25m
kube-system   ucp-nvidia-device-plugin-mbl74             1/1     Running   0          3h55m


$ ./kubectl get service --all-namespaces
NAMESPACE     NAME              TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
default       kubernetes        ClusterIP   10.96.0.1       <none>        443/TCP                      5h28m
kong          kong-kong-proxy   NodePort    10.96.154.9     <none>        80:32780/TCP,443:34536/TCP   10m
kube-system   compose-api       ClusterIP   10.96.51.39     <none>        443/TCP                      5h26m
kube-system   kube-dns          ClusterIP   10.96.0.10      <none>        53/UDP,53/TCP,9153/TCP       5h27m
kube-system   ucp-controller    ClusterIP   10.96.219.147   <none>        443/TCP,12379/TCP            5h26m
kube-system   ucp-metrics       ClusterIP   10.96.206.212   <none>        443/TCP                      5h26m






Check the Kong Proxy
$ http :32780
HTTP/1.1 404 Not Found
Connection: keep-alive
Content-Length: 48
Content-Type: application/json; charset=utf-8
Date: Mon, 18 Jan 2021 22:21:44 GMT
Server: kong/2.2.1
X-Kong-Response-Latency: 0

{
    "message": "no Route matched with those values"
}



Sample App Installation
This Sample Application will be use to show Kong for Kubernetes Ingress Controller capabilities:

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: sample
  namespace: default
  labels:
    app: sample
spec:
  type: ClusterIP
  ports:
  - port: 5000
    name: http
  selector:
    app: sample
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sample
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sample
  template:
    metadata:
      labels:
        app: sample
        version: v1
    spec:
      containers:
      - name: sample
        image: claudioacquaviva/sampleapp
        ports:
        - containerPort: 5000
EOF




$ kubectl get services --all-namespaces
NAMESPACE     NAME              TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
default       kubernetes        ClusterIP   10.96.0.1       <none>        443/TCP                      5h37m
default       sample            ClusterIP   10.96.134.16    <none>        5000/TCP                     5s
kong          kong-kong-proxy   NodePort    10.96.154.9     <none>        80:32780/TCP,443:34536/TCP   20m
kube-system   compose-api       ClusterIP   10.96.51.39     <none>        443/TCP                      5h36m
kube-system   kube-dns          ClusterIP   10.96.0.10      <none>        53/UDP,53/TCP,9153/TCP       5h36m
kube-system   ucp-controller    ClusterIP   10.96.219.147   <none>        443/TCP,12379/TCP            5h36m
kube-system   ucp-metrics       ClusterIP   10.96.206.212   <none>        443/TCP                      5h36m




$ kubectl get pod --all-namespaces
NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE
default       sample-7d97fc95c-h27w9                     1/1     Running   0          25s
kong          kong-kong-75467bff7f-5z4ll                 2/2     Running   0          20m
kube-system   calico-kube-controllers-784d968c7f-lw8t8   1/1     Running   0          5h37m
kube-system   calico-node-lgscz                          2/2     Running   0          5h37m
kube-system   calico-node-mc8b8                          2/2     Running   0          4h6m
kube-system   compose-api-fc595464f-rt56n                1/1     Running   0          5h36m
kube-system   compose-c78b96dc8-xvnlj                    1/1     Running   0          5h36m
kube-system   coredns-665c6f959f-p49ss                   1/1     Running   0          5h37m
kube-system   coredns-665c6f959f-sr56w                   1/1     Running   0          5h37m
kube-system   ucp-metrics-f2vz6                          3/3     Running   1          5h36m
kube-system   ucp-nvidia-device-plugin-cwrpg             1/1     Running   0          5h36m
kube-system   ucp-nvidia-device-plugin-mbl74             1/1     Running   0          4h6m











Ingresses and Policies
Create a Service and a Route using CRDs
In order to expose "sample" through K4K8S, we're going to create a specific "/sampleroute" route. Initially, the route is totally open and can be consumed freely. The next sections enable, as their names suggest, an API Key and a Rate Limiting mechanism to protect the route.

cat <<EOF | kubectl apply -f -
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: sampleroute
  namespace: default
  annotations:
    kubernetes.io/ingress.class: kong
    konghq.com/strip-path: "true"
spec:
  rules:
  - http:
      paths:
        - path: /sampleroute
          backend:
            serviceName: sample
            servicePort: 5000
EOF


Checking the Ingress
$ kubectl get ingress --all-namespaces
NAMESPACE   NAME          CLASS    HOSTS   ADDRESS         PORTS   AGE
default     sampleroute   <none>   *       172.31.13.110   80      7s

$ kubectl describe ingress sampleroute
Name:             sampleroute
Namespace:        default
Address:          172.31.13.110
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
Rules:
  Host        Path  Backends
  ----        ----  --------
  *           
              /sampleroute   sample:5000 (192.168.143.137:5000)
Annotations:  konghq.com/strip-path: true
              kubernetes.io/ingress.class: kong
Events:       <none>



Testing the Ingress
$ http :32780/sampleroute/hello
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 45
Content-Type: text/html; charset=utf-8
Date: Mon, 18 Jan 2021 22:39:52 GMT
Server: Werkzeug/1.0.1 Python/3.7.4
Via: kong/2.2.1
X-Kong-Proxy-Latency: 0
X-Kong-Upstream-Latency: 2

Hello World, Kong: 2021-01-18 22:39:52.113812


K4K8S - Rate Limiting Policy Definition
Since we have the Microservice exposed through a route defined in the Ingress Controller, let's protect it with a Rate Limiting Policy first.


Create the plugin
cat <<EOF | kubectl apply -f -
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: rl-by-minute
  namespace: default
config:
  minute: 3
  policy: local
plugin: rate-limiting
EOF


Check the plugin
$ kubectl get kongplugins
NAME           PLUGIN-TYPE     AGE
rl-by-minute   rate-limiting   21s


$ kubectl describe kongplugin rl-by-minute
Name:         rl-by-minute
Namespace:    default
Labels:       <none>
Annotations:  <none>
API Version:  configuration.konghq.com/v1
Config:
  Minute:  3
  Policy:  local
Kind:      KongPlugin
Metadata:
  Creation Timestamp:  2021-01-18T22:40:19Z
  Generation:          1
  Managed Fields:
    API Version:  configuration.konghq.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:config:
        .:
        f:minute:
        f:policy:
      f:metadata:
        f:annotations:
          .:
          f:kubectl.kubernetes.io/last-applied-configuration:
      f:plugin:
    Manager:         kubectl-client-side-apply
    Operation:       Update
    Time:            2021-01-18T22:40:19Z
  Resource Version:  54191
  Self Link:         /apis/configuration.konghq.com/v1/namespaces/default/kongplugins/rl-by-minute
  UID:               0e420b0e-177d-4e42-a66a-6373b2d110f4
Plugin:              rate-limiting
Events:              <none>



Apply the plugin to the route
kubectl patch ingress sampleroute -p '{"metadata":{"annotations":{"konghq.com/plugins":"rl-by-minute"}}}'

$ kubectl describe ingress sampleroute
Name:             sampleroute
Namespace:        default
Address:          172.31.13.110
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
Rules:
  Host        Path  Backends
  ----        ----  --------
  *           
              /sampleroute   sample:5000 (192.168.143.137:5000)
Annotations:  konghq.com/plugins: rl-by-minute
              konghq.com/strip-path: true
              kubernetes.io/ingress.class: kong
Events:       <none>



Deleting the annotation
In case you want to disapply the plugin to the ingress run:
$ kubectl annotate ingress sampleroute konghq.com/plugins-



Test the plugin
Consume the route:

$ http :32780/sampleroute/hello
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 45
Content-Type: text/html; charset=utf-8
Date: Mon, 18 Jan 2021 22:41:24 GMT
RateLimit-Limit: 3
RateLimit-Remaining: 2
RateLimit-Reset: 36
Server: Werkzeug/1.0.1 Python/3.7.4
Via: kong/2.2.1
X-Kong-Proxy-Latency: 1
X-Kong-Upstream-Latency: 1
X-RateLimit-Limit-Minute: 3
X-RateLimit-Remaining-Minute: 2

Hello World, Kong: 2021-01-18 22:41:24.693249


As expected, we get an error for the 4th request::

$ http :32780/sampleroute/hello
HTTP/1.1 429 Too Many Requests
Connection: keep-alive
Content-Length: 41
Content-Type: application/json; charset=utf-8
Date: Mon, 18 Jan 2021 22:41:45 GMT
RateLimit-Limit: 3
RateLimit-Remaining: 0
RateLimit-Reset: 15
Retry-After: 15
Server: kong/2.2.1
X-Kong-Response-Latency: 1
X-RateLimit-Limit-Minute: 3
X-RateLimit-Remaining-Minute: 0

{
    "message": "API rate limit exceeded"
}




K4K8S - API Key Policy Definition
Now, let's add an API Key Policy to this route:


Create the plugin
cat <<EOF | kubectl apply -f -
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: apikey
  namespace: default
plugin: key-auth
EOF


Check the plugin
$ kubectl get kongplugins
NAME           PLUGIN-TYPE     AGE
apikey         key-auth        63s
rl-by-minute   rate-limiting   141m


$ kubectl describe kongplugins apikey
Name:         apikey
Namespace:    default
Labels:       <none>
Annotations:  <none>
API Version:  configuration.konghq.com/v1
Kind:         KongPlugin
Metadata:
  Creation Timestamp:  2021-01-18T22:42:28Z
  Generation:          1
  Managed Fields:
    API Version:  configuration.konghq.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:metadata:
        f:annotations:
          .:
          f:kubectl.kubernetes.io/last-applied-configuration:
      f:plugin:
    Manager:         kubectl-client-side-apply
    Operation:       Update
    Time:            2021-01-18T22:42:28Z
  Resource Version:  54547
  Self Link:         /apis/configuration.konghq.com/v1/namespaces/default/kongplugins/apikey
  UID:               9c43d7fd-60cf-4b6d-9469-e6ef7200a800
Plugin:              key-auth
Events:              <none>


Apply the plugin to the route
Now, let's add an API Key Policy to this route keeping the original Rate Limiting plugin:

kubectl patch ingress sampleroute -p '{"metadata":{"annotations":{"konghq.com/plugins":"apikey, rl-by-minute"}}}'

$ kubectl describe ingress sampleroute
Name:             sampleroute
Namespace:        default
Address:          172.31.13.110
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
Rules:
  Host        Path  Backends
  ----        ----  --------
  *           
              /sampleroute   sample:5000 (192.168.143.137:5000)
Annotations:  konghq.com/plugins: apikey, rl-by-minute
              konghq.com/strip-path: true
              kubernetes.io/ingress.class: kong
Events:       <none>



Test the plugin
As expected, if we try to consume the route we get an error:

$ http :32780/sampleroute/hello
HTTP/1.1 401 Unauthorized
Connection: keep-alive
Content-Length: 45
Content-Type: application/json; charset=utf-8
Date: Mon, 18 Jan 2021 22:43:27 GMT
Server: kong/2.2.1
WWW-Authenticate: Key realm="kong"
X-Kong-Response-Latency: 1

{
    "message": "No API key found in request"
}


Provisioning a Key
$ kubectl create secret generic consumerapikey --from-literal=kongCredType=key-auth --from-literal=key=kong-secret
secret/consumerapikey created

If you want to delete it run:

$ kubectl delete secret consumerapikey


Creating a Consumer with the Key
cat <<EOF | kubectl apply -f -
apiVersion: configuration.konghq.com/v1
kind: KongConsumer
metadata:
  name: consumer1
  namespace: default
  annotations:
    kubernetes.io/ingress.class: kong
username: consumer1
credentials:
- consumerapikey
EOF


Check the Consumer
$ kubectl get kongconsumer
NAME        USERNAME    AGE
consumer1   consumer1   2m37s

$ kubectl describe kongconsumer consumer1
Name:         consumer1
Namespace:    default
Labels:       <none>
Annotations:  kubernetes.io/ingress.class: kong
API Version:  configuration.konghq.com/v1
Credentials:
  consumerapikey
Kind:  KongConsumer
Metadata:
  Creation Timestamp:  2021-01-18T22:43:56Z
  Generation:          1
  Managed Fields:
    API Version:  configuration.konghq.com/v1
    Fields Type:  FieldsV1
    fieldsV1:
      f:credentials:
      f:metadata:
        f:annotations:
          .:
          f:kubectl.kubernetes.io/last-applied-configuration:
          f:kubernetes.io/ingress.class:
      f:username:
    Manager:         kubectl-client-side-apply
    Operation:       Update
    Time:            2021-01-18T22:43:56Z
  Resource Version:  54792
  Self Link:         /apis/configuration.konghq.com/v1/namespaces/default/kongconsumers/consumer1
  UID:               d8745b13-7dff-4d42-a1c9-dd7d1226df75
Username:            consumer1
Events:              <none>


Consume the route with the API Key
$ http :32780/sampleroute/hello apikey:kong-secret
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 45
Content-Type: text/html; charset=utf-8
Date: Mon, 18 Jan 2021 22:44:33 GMT
RateLimit-Limit: 3
RateLimit-Remaining: 2
RateLimit-Reset: 27
Server: Werkzeug/1.0.1 Python/3.7.4
Via: kong/2.2.1
X-Kong-Proxy-Latency: 1
X-Kong-Upstream-Latency: 2
X-RateLimit-Limit-Minute: 3
X-RateLimit-Remaining-Minute: 2

Hello World, Kong: 2021-01-18 22:44:33.099767




Getting the Rate Limiting error
Again, if we try the 4th request in a single minute we get the rate limiting error

$ http :32780/sampleroute/hello apikey:kong-secret
HTTP/1.1 429 Too Many Requests
Connection: keep-alive
Content-Length: 41
Content-Type: application/json; charset=utf-8
Date: Mon, 18 Jan 2021 22:44:48 GMT
RateLimit-Limit: 3
RateLimit-Remaining: 0
RateLimit-Reset: 12
Retry-After: 12
Server: kong/2.2.1
X-Kong-Response-Latency: 0
X-RateLimit-Limit-Minute: 3
X-RateLimit-Remaining-Minute: 0

{
    "message": "API rate limit exceeded"
}




