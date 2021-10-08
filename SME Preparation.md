SME Preparation
~~~~~~~~~~~~~~~

INTRO:
Kubernetes is an open-source container orchestrator tool used for Deploying, Scaling and Managing Containerized workloads.

The kubernetes architecture is mainly divided into a Control plane and a Data plane.

Control plane:
    The control plane consists of master nodes which are responsible for managing the deployed workloads to the Cluster.

    The control plane run the components such as an API server, kube-scheduler, ETCD, kube-controller manager, cloud-controller manager.

    API server:
        > API server is the front-end of the k8s cluster. All the requests within the cluster go through the API server.
        > The Kubernetes API server validates and configures data for the API objects which include (pods, services, replication controllers and others) and updates the corresponding objects in etcd.

        The default authorization mode for EKS API server is "--authorization-mode=Node,RBAC"
            The Node authroization mode is requried specifically to authorize API requests made by kubelets.
            The RBAC mode is used to regulate access to cluster resources based on RBAC policies. These policies define who can perform what actions and are specified by a set of Kubernetes API objects called Roles,RoleBindings, ClusterRoles and ClusterRoleBindings.

    kube-scheduler:
        > It is a control plane component that watches for newly created Pods with no assigned node, and selects a node for them to run on.
        > Some of the factors taken into account for scheduling decisions include:
          i. Individual resource requirements.
         ii. Hardware/software/policy constraints.
        iii. Affinity and anti-affinity specifications etc
         iv. Taints and Tolerations.

        Scheduling Policy: A scheduling Policy can be used to specify the 'predicates' and 'priorities' that the kube-scheduler runs to filter and score nodes, respectively.
            Predicates: these aid in filtering nodes based on the pods requirements for CPU/mem resources, ports, volumes etc
            Priorities: When multiple nodes qualify for pod placement, these aid in scoring the nodes based on the priority defined in the scheduler policy.

    ETCD:
        > ETCD is a distributed storage system that backs up the cluster state.
        > It is a consistent and highly-available key value store used to store cluster state information and data belonging to the resources deployed to the cluster.
        > API server is the only component that talks to ETCD.
        How API server authenticates with ETCD?
            > It uses the apiserver-etcd-client.crt and etcd ca.crt to authenticate with the etcd server. These certs are passed as flags to the API server during its initialization.

    kube-controller manager:
        > It is a control plane component that runs and manages the controllers.
        > Some of the controllers it manages are namely.
        a. Node controller: Responsible for noticing and responding when nodes go down.
        b. Job controller: Watches for Job objects that represent individual tasks, then creates Pods to run those tasks to completion.
        c. Endpoints controller: Populates the Endpoints object (that is, joins Services & Pods).
        d. Service Account & Token controllers: Create default accounts and API access tokens for newly created namespaces.

    cloud-controller manager:
        > It is a control plane component that integrates cloud-specific control logic.
        > It lets you link your cluster to your cloud provider's API.
        > The cloud-controller-manager only runs controllers that are specific to your cloud provider.

Data plane:
    The data plane consists of worker nodes also referred to as just nodes run the containerized workloads. There a few node components that run on every node.

    Kubelet: 
        > kubelet is an agent that runs on every worker node responsible for bootstrapping the node and registering the node with the Control plane master and also ensures the containers in the pods are running/healthy as per the pod spec provided. It does not manage the containers which are not created by k8s.

    Kube-proxy: 
        > kube-proxy is a network proxy that runs on each node in your cluster, implementing the Kubernetes Services concept.
        > kube-proxy maintains network rules on nodes and performs connection forwarding. These network rules allow network communication to your Pods from from both within and outside the cluster.
    
    CNI:
        > Container network interface (VPC CNI plugin) is responsible for assigning an IP address to pod and setup pod networking.
    
    Container Runtime: 
        > Container runtime also known as docker/containerd is responsible for creating and destroying the containers.

    CoreDNS: 
        > CoreDNS is an add-on that is deployed to the cluster as a deployment. It manages the DNS resolution of endpoints within the cluster and forwards the DNS queries to the underlying hosts' DNS server if the endpoint is a public endpoint (internet).
        > The underlying hosts' DNS configuration depends on the DHCP options setup for the VPC in which the ec2 instance is launched.

EKS Features and offerings:
~~~~~~~~~~~~~~~~~~~~~~~~~~
> The EKS service sets up and manages the Kubernetes control plane for you. It helps with automating the deployment, scaling, and management of your containerized applications.
> EKS maintains resilience for the Kubernetes control plane by replicating it across multiple Availability Zones. Unhealthy control plane instances are automatically detected and replaced, patches are applied automatically and version upgrades are available on-demand.
> Amazon EKS lets you use existing tooling and plugins from the Kubernetes community. There is full compatibility between Amazon EKS and applications running on other Kubernetes environments. This makes it easy to migrate existing Kubernetes applications to Amazon EKS.
> Secure and Encrypted communication channels are automatically setup between the worker nodes and the Control plane making your infrastructure running on Amazon EKS Secure by default.
> Amazon EKS uses Amazon VPC network policies to restrict traffic between control plane components to within a single cluster. Control plane components for a cluster can't view or receive communication from other clusters or other AWS accounts, except as authorized with Kubernetes RBAC policies. This secure and highly available configuration makes Amazon EKS reliable and recommended for production workloads.  
> AWS actively works with kubernetes community and also makes contribution to kubernetes code base that helps EKS users take advantage of AWS services and features.
> Amazon EKS is certified kubernetes conformant meaning applications managed by standard kubernetes are also fully compatible with EKS.
> EKS removes the complexity of deploying a highly available & scalable control plane by providing a fully managed kubernetes service.
> EKS Clusters are created in your Amazon VPC allowing you to use your own SecurityGroups, Subnets and ACLs.
> EKS Clusters being a single tenant design, provides users with high level of isolation and helps build highly secure and reliable applications.
> EKS integrates kubernetes RBAC with AWS IAM using AWS IAM Authenticator. You can assign RBAC roles directly to each IAM user/IAM Role to granularly control the access to the kubernetes clusters.
> Also EKS is integrated with Amazon CloudWatch and CloudTrail to provide visibility and audit cluster and user activity. It also provides the Kubernetes control plane logs by streaming them to CloudWatch logs.
> It also provides a CLI tool called 'eksctl' for creating and managing clusters on EKS. It uses CloudFormation in the back-end to create/update/delete clusters and its resources.

Amazon EKS vs. ECS:
~~~~~~~~~~~~~~~~~~~
https://cloud.netapp.com/blog/aws-cvo-blg-aws-ecs-vs-eks-6-key-differences
https://aws.amazon.com/blogs/containers/amazon-ecs-vs-amazon-eks-making-sense-of-aws-container-services/

While both Amazon EKS and Amazon ECS offer similar integrations with other AWS services, each service provides different use cases for managing containerized applications and differ in areas such as networking and ease of deployment.

So should you use Amazon EKS or ECS? It truly depends on your organization’s needs. While pricing is relatively similar between the two services, Amazon EKS has a minimal charge per cluster per month, which has the potential to add up quickly.

If you’re already running workloads on Kubernetes, Amazon EKS might be a better fit for your DevOps teams. 
If you haven’t worked much with containers yet, ECS might be the best option. Bottom line— determine your architectural needs and dive deep into each solution’s limitations.

EKS Cluster Upgrades:
~~~~~~~~~~~~~~~~~~~~~
> The first and the foremost thing to do before upgrading a cluster to a newer version is to review the changes introduced in the new version. Checks for any new API's being introduced or the old ones getting deprecated/removed. It is always recommended to test the application behavior against the new versions before upgrading the production clusters.
> To upgrade the cluster, EKS requires 2-3 free IP addresses in the subnets provided during cluster creation. If there aren't any free IPs, the update can fail.
> Also one needs to make sure the Security Groups/Subnets used during cluster creation are not deleted, else the update can fail.
> Before upgrading the Kubernetes Control plane version, keep in check the worker node/kubelet version and make sure if satisfies the version skew, which is the nodes may only be up to two minor versions older.
> If the cluster data-plane consists of Fargate nodes, the pods needs to be recycled after the control plane update is finished.
> Ensure that the proper pod security policies (PSP) are in place before the upgrade to avoid any issues.
    PSP - The PodSecurityPolicy objects define a set of conditions that a pod must run with, in order to be accepted into the system. It is a cluster-level resource that controls security sensitive aspects of the pod specification.
> Because Amazon EKS runs a highly available control plane, you can update only one minor version at a time.
> If you deployed the Kubernetes Cluster Autoscaler to your EKS clusters, before updating the cluster, make sure to disable the CA for time being and also update the Cluster Autoscaler to the latest version that matches your upgraded EKS major and minor versions.
> One should also update the VPC CNI, CoreDNS, and kube-proxy add-ons post the control plane upgrade.
> Enable control plane audit logs for troubleshooting purposes just in case.
> When upgrading/scaling cluster data plane with a large number of worker nodes one might quickly exhaust the IPs in the subnets due to the CNI default ENI/IP warm-pool settings (https://docs.aws.amazon.com/eks/latest/userguide/cni-env-vars.html). This problem can be solved by right-sizing the VPC/subnets and distributing nodes among them properly.
> When upgrading Large EKS data planes, it is possible that new nodes being launched are stuck in a NotReady due to CNI plugin being unable to assign IPs to the Primary ENIs. Besides the lack of IPs in the subnets, there could also be EC2 API throttling issues. The throttling is usually observed on ec2:AssignPrivateIpAddresses, ec2:CreateNetworkInterface, ec2:DescribeNetworkInterfaces, DescribeCluster EC2 API calls. This problem can be mitigated by increasing the API rate limits by working with the service teams and also by performing a more controlled scaling of nodes.

EKS Authentication and Authorization:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every request that you send to the kubernetes API server goes through three phases:
    a. Authentication
    b. Authorization
    c. Admission control

Amazon EKS uses IAM to provide authentication to your Kubernetes cluster (through the aws eks get-token command, available in version 1.16.156 or later of the AWS CLI, or the AWS IAM Authenticator for Kubernetes) but it still relies on native Kubernetes Role Based Access Control (RBAC) for authorization.

    AWS IAM Authenticator: 
    > AWS IAM Authenticator is a tool we use in EKS to authenticate against a Kubernetes cluster.

    Authentication:    
    ~~~~~~~~~~~~~~
    1. To interact with the EKS Cluster, we use a command line utility called kubectl, which is essentially a wrapper script around cURL. For every kubectl command that you execute the kubectl client tries to communicate with the Cluster's API server to perform the suggested operation. To be able to communicate with the API server, it needs to first authenticate itself, which it does by executing the 'aws eks get-token' command or by invoking the AWS IAM AUthenticator.

    2. The kubectl client by default reads the kubeconfig file located at ~/.kube/config. One can also use a different kubeconfig file by passing the flag --kubeconfig with the $Path to the kubeconfig file to use for CLI requests.

        kubeconfig command example:
            exec:
              apiVersion: client.authentication.k8s.io/v1alpha1
              args:
              - token
              - -i
              - <Cluster-Name>
              command: aws-iam-authenticator.

    3. The AWS IAM authenticator generates an STS GetCallerIdentity presigned URL which is returned as a base64 encoded token and is sent to the API server within a 'ExecCredential' kind object.
    4. kubectl uses the token returned by the aws-iam-authenticator command as a bearer token and is sent in its requets to API server.
    5. There is an AWS IAM Authenticator running on the control plane also, which decodes this token to retrieve the user ARN, AccountID,AccessKeyID etc and verifies the identity of the caller with STS (Secure Token Service) .

whenever the API server receives a request, it forwards the IAM identity token in the request to the webhook service. The webhook service first verifies whether the obtained IAM identity is a valid IAM identity with the AWS IAM service.

    6. Once the IAM entity is verified, the webhook service consults a ConfigMap object called 'aws-auth' to check whether the IAM identity corresponds to a valid user of the cluster and a TokenReview object is returned with the kubnetes username & group information along with attribute 'authenticated: true' in its response.
    7. If the authentication is successful the API server processes the request and sends the response back to the kubectl client. If not, the request is rejected.

    Authorization:
    ~~~~~~~~~~~~~~
    > In the aws-auth ConfigMap we define mappings for IAM identities to kubernetes “usernames” and “groups”.
    > For Kubernetes RBAC authorisation, these policies define who can do what are specified by a set of Kubernetes API objects called Roles and RoleBindings. 
    > There is also an RBAC default role called 'cluster-admin', which allows all possible Kubernetes actions. Also there is a default role binding that binds the cluster-admin role to the system:masters group.
    > Within the aws-auth configMap when a user gets assigned to group system:masters, all kubernetes actions by that user are allowed.

https://itnext.io/how-does-client-authentication-work-on-amazon-eks-c4f2b90d943b#7ede 

Node Bootstrap Initialization:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Vanilla Kubernetes:
> The node registers with the EKS cluster using client and server certificates. But in EKS worker nodes are registered with control plane using IAM.
> Kubelet uses NodeInstanceRole along with aws-iam-authenticator to authenticate itself.

In the bootstrap initialization process, the following occurs:

    1. The EKS Optimized AMI has a bootstrap.sh script located at /etc/eks directory and is executed when the node is first initialized.
        - Bootstrap script reads if any of the EKS API server endpoint, cluster CA certificate, Cluster DNS IP arguments are passed to the script, if not it executes the DescribeCluster EKS API call to fetch the required information.
        - Sets up the max pods based on instance type using the file eni-max-pods.txt (https://github.com/awslabs/amazon-eks-ami/blob/master/files/eni-max-pods.txt) and update kubelet config with max pods.
        - Determines pause container image to use and populates the /etc/systemd/system/kubelet.service.d/10-kubelet-args.conf file. This image is used to create the pause container for setting up pod networking when a new pod is scheduled onto a worker node.
        - Creates a 'kubeconfig' file which will be used by kubelet to authenticate to the api-server.
        - Sets 'kubeReserved' and 'evictionHard' within the kubelet configuration file (/etc/kubernetes/kubelet/kubelet-config.json) to reserve CPU and memory resources for the kubelet.
        - Adds extra configuration to the kubelet.service and if any kubelet-extra-arguments that passed via the arguments to the script.
        - Updates custom docker configuration.
        - Starts and enables kubelet service.
    2. kubelet connects to the API server using the kubeconfig file and authenticates itself with the API server and establishes a TLS connection.
    3. kubelet then creates a CSR for itself with the signerName set to kubernetes.io/kube-apiserver-client-kubelet.
    8. CSR is approved in one of two ways:
        If configured, kube-controller-manager automatically approves the CSR.
        If configured, an outside process, possibly a person, approves the CSR using the Kubernetes API or via kubectl
            a. Certificate is created and issued for the kubelet.
    9. kubelet retrieves the certificate.
    10. kubelet creates a proper kubeconfig with the key and signed certificate.
    11. From here the system pods aws-node and kube-proxy are started. Once they are started successfully the node goes into a ready state.

Worker node not joining cluster troubleshooting:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    > Run 'kubectl get nodes' to check if nodes are not joining at all or if they are in a Not-Ready state.
    > Check the worker node instance user-data execution for any errors during bootstrap.sh script execution from EC2 admiral page console output. On the worker node the logs are located at /var/log/cloud-init-output.log.
    > Check the worker node and EKS Cluster control plane securityGroups to verify if the traffic if ports 10250 and 443 are open to enable communication between the control plane and data plane.
    > Check if the worker nodes are launched in a private or public subnet and if the instances have connectivity to internet or not. In case of private worker nodes make sure required VPC endpoints are created.
    > Check the worker node instance profile and verify if the required IAM policies are attached to it.
    > Check the kubelet logs on the worker node by executing 'journalctl -u kubelet'.
    > If the CNI plugin is failing to come up successfully, check the logs in /var/log/aws-routed-eni/ location.
    > If there are Unauthorized error within the kubelet, check if the /var/lib/kubelet/kubeconfig is configured correctly with the correct cluster API server endpoint and make sure the CA certificate in /etc/kubernetes/pki folder is the same as the Cluster CA certificate.
    > Worker node use its instance profile and the corresponding role should be available with “aws-auth“ file (cluster) so that node should be able to authorize and register with the cluster.

How EKS Control plane approves kubelet CSR:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    > When kubelet starts on the worker node, it will submit a CSR to control plane for approval. 
    > The permissions to submit a CSR are provided by ClusterRole eks:node-bootstrapper.
    > The ClusterRole to IAM NodeInstanceRole mapping is configured in aws-auth ConfigMap.
    > Once approved, kubelet will grab the issued certificate and use for serving incoming requests on port 10250.
    > This is required for API server to verify it is talking to the authenticated kubelet. 
    > Without proper certificate, commands like kubectl exec, kubectl logs will fail because API could not establish a trusted connection with kubelet.

High level Pod launch workflow flow:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  - A command to create a pod object is sent to api server by user. 
  - API server will then use webhooks to mutate/validate the pod object and eventually persists it to ETCD.
  - A Scheduler within the control plane continuously watches for new pod object that do not have a node assigned to them.
  - Scheduler will then take into account factors like pod affinities, taints and tolerations etc to filter the nodes and find a suitable node for the pod.
    
    Scheduling Policy: A scheduling Policy can be used to specify the 'predicates' and 'priorities' that the kube-scheduler runs to filter and score nodes, respectively.
        Predicates: these aid in filtering nodes based on the pods requirements for CPU/mem resources, ports, volumes etc
        Priorities: When multiple nodes qualify for pod placement, these aid in scoring the nodes based on the priority defined in the scheduler policy.
  
  - Scheduler will then schedule the pod onto the node.
  - From here the kubelet takes over and uses the CNI plugin setup on the worker node to start the requested containers and sends it status back to the API server.

Node selection in kube-scheduler

kube-scheduler selects a node for the pod in a 2-step operation:

    Filtering
    Scoring

The filtering step finds the set of Nodes where it's feasible to schedule the Pod. For example, the PodFitsResources filter checks whether a candidate Node has enough available resource to meet a Pod's specific resource requests. After this step, the node list contains any suitable Nodes; often, there will be more than one. If the list is empty, that Pod isn't (yet) schedulable.

In the scoring step, the scheduler ranks the remaining nodes to choose the most suitable Pod placement. The scheduler assigns a score to each Node that survived filtering, basing this score on the active scoring rules.

Finally, kube-scheduler assigns the Pod to the Node with the highest ranking. If there is more than one node with equal scores, kube-scheduler selects one of these at random.

VPC CNI workflow (pod provisioning flow):
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 VPC-CNI comprises of 2 parts
    - CNI plugin: responsible for setting up the pod networking.
    - LIPAMD: responsible for running AWS api calls to create, attach, detach, delete ENI's and Secondary IP's , attach and detach SG's to the ENI's
    At startup of the aws-node pod it will mount two directories /etc/cni/net.d/, /opt/cni/bin/ onto the node using mount volumes.
        - /etc/cni/net.d  ---> will copy 10-aws.conflist which has info about the SNAT, capabilities and CNI name.

Workflow version 1:
~~~~~~~~~~~~~~~~~~
    > kubelet will invoke the CRI (docker) to create a pause container and pod network namespace.
    > container runtime then returns pause container Id and n/w namespace info to the kubelet.
    > kubelet then invokes the CNI binary to setup the network stack for the pause container using an ADD Command, to add IP to the pause container network.
    > CNI binary will now make a GRPC call to the IPAMD in order to associate IP address to the container. 
    > The IPAMD goes into a reconcile loop to check the warm pool for available IPs/ENIs and assigns an IP to the container and updates the IPAMD data store.
    > IPAMD after associating the IP to the container sends back the info to the CNI with route table info of the ENI where the IP is attached.
    > CNI will now create a veth pair b/w pod network namespace and virtual ENI on the host.
    > CNI will set the IP on the container interface and and sets default gateway to host network.
    > CNI will wire up the host n/w by setting ip rule and ip routes to enable communication both within and outside the host.
       ip rules will show which table to go for communication within the host (local) and outside the host (main).

Workflow version 2:
    1. Kubelet will instruct CRI to create PAUSE container and network NameSpace. Then CRI will send back the info about the created container id of pause and network namespace to the kubelet.
    2. CNI is then invoked which Makes a GRPC call to IPAMD asking for IP address.
    3. IPAMD will give ip and route table info.
    4. CNI Bin will create Veth pair. (one on host and one on container network namespace)
      - Create a veth pair and have **one veth on host namespace and one veth on Pod's namespace**
        - `ip link add veth-1 type veth peer name veth-1c  /* on host namespace */`
        - `ip link set veth-1c netns ns1  /* move veth-1c to Pod's namespace ns1 */`
        - `ip link set veth-1 up /* bring up veth-1 */`
        - `ip netns exec ns1 ip link set veth-1c up /* bring up veth-1c */`
    5. set ip on container eth. set default gateway. set Static ARP to reach to host. (by default snat will be there do all traffic will go through eth0)
        - Assign the IP address to Pod's eth0
        - Add default gateway and default route to Pod's route table
        - Add a static ARP entry for default gateway
          - `To assign IP address 20.0.49.215 to Pod's namespace ns1`
          - `ip netns exec ns1 ip addr add 20.0.49.215/32 dev veth-1c /* assign a IP address to veth-1c */`
          - `ip netns exec ns1 ip route add 169.254.1.1 dev veth-1c /* add default gateway */`
          - `ip netns exec ns1 ip route add default via 169.254.1.1 dev veth-1c /* add default route */`
          - `ip netns exec ns1 arp -i veth-1c -s 169.254.1.1 <veth-1's mac> /* add static ARP entry for default gateway */`
    6. CNI bin will setup ip rules and ip route.
       - On host side, add host route so that incoming Pod's traffic can be routed to Pod.
        `/* Pod's IP address is 20.0.49.215 */`
        `ip route add 20.0.49.215/32 dev veth-1 /* add host route */`
    7. CNI will tell kubelet that its job is done.

Requests and Limits:
~~~~~~~~~~~~~~~~~~~
    > Requests: Containers can specify a cpu/memory request, which is the minimum amount of the resource that the system will guarantee to the container.
    > Limits: Containers can specify a cpu/memory limit, which is the maximum amount of the resource that the system will allow the container to use.

Scheduler working high-level:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    > On a high level the scheduler controller maintains a queue of pods to be deployed to the cluster.
    > For each workload/pod in the queue, the scheduler looks for a node with enough available compute resources to fulfill the requests specified in the pod spec and assigns the pod to that node.
    > Limits are ignored during scheduling.
    > When a node hits its limit for memory or disk, pods can be evicted and sent back to the scheduler for re-deployment on another node.

Quality of Service classes (QoS):
A pod is - 
   > Guaranteed : If every container in the pod has explicit requests and limits for CPU and Memory and limits exactly match the requests.
   > Best Effort: If any container in the pod does not have explicit requests and limits.
   > Burst-able: If every container in the pod has explicit requests and limits for CPU and Memory and limits are greater than the requested amount for at least 1 container.

Fargate Scheduler:
~~~~~~~~~~~~~~~~~~
https://broadcast.amazon.com/videos/312159

    > kubernetes Fargate scheduler + node life cycle controller 
    > Scheduler tries to implement a state machine in the backend.
    > Pending pod -> Task provisioned -> Task running/Node Registered/pod is still pending -> Pod scheduled/task running/node registered -> Pod running.

Fargate Defaults:
~~~~~~~~~~~~~~~~~
    > The sum of the requests for all containers is calculated and rounded off to the next biggest fargate configuration.
    > If requests/limits are not specified a default of 0.25vCPU and 0.5GB memory are allocated.
    > Fargate reserves 256MB to each pod's memory reservation for kubernetes system components such as kubelet, kube-proxy, containerd, EFS, firelens etc
    > Auto mutates requests = limits if not specified.

What are the limitations of EKS Fargate?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    > can not run pods with privileged escalation, host network, nodeSelector , capabilities.
    > takes around 2 mins for a pod to be launched.
    > VPC DNS host name must not be custom.
   

Fargate troubleshooting:
~~~~~~~~~~~~~~~~~~~~~~~~
    > Describe the pod.
    > Check the 'aws-auth' for the fargate pod execution role.
    > Check if the Fargate profile has proper subnets which are not public.
    > Check if the pod are launched in the correct name space with specific pod selectors as specified in the fargate profile.
    > Check if the DNS in DHCP options is custom.
    > Check if the scheduler is default of fargate one.
    > Investigate further using control plane logs specifically scheduler and api server logs.

EKS Windows:
~~~~~~~~~~~

1. Enable windows support for EKS Cluster.
[] Windows support - https://docs.aws.amazon.com/eks/latest/userguide/windows-support.html

> To enable windows support for your EKS Cluster, you have to deploy the VPC resource controller and VPC Admission Controller webhook for your cluster.

VPC Resource Controller:
~~~~~~~~~~~~~~~~~~~~~~~

Currently we have two versions of the controller, one is running on the worker node, the other is running in Control plane.
    > Windows: The first one running on worker nodes is used for enabling Windows support for cluster, manages IP addresses for all windows worker nodes. (Similar to IPAMD for linux).
        - The plan is to eventually move this controller also to control plane, making it an EKS Managed controller.
    > Linux: The second one that's running on control plane is for managing trunk interfaces and allocating branch network interfaces to pods (Used to enable SecurityGroups per pod feature).

Key differences in IP Address Management on windows vs linux: 
    - On linux nodes there is an IPAMD daemon that is running on each worker node to manage the IP address assignment.
    - On windows, the controller performs IP address management across all the worker nodes.

    - On windows, Since the controller is not running on the same node as the CNI binary, the VPC resource controller annotates the pod with the IP address, which the CNI binary/plugin then uses to setup pod networking.
    - On linux, the CNI plugin makes a GRPC call to the IPAMD daemon to get the IP address.

    - On windows, to limit the number of pods it uses extended resources.
    - On linux to limit the number of pods on a node, there is a provision to pass --max-pods flag to the kubelet.

Windows node provisioning workflow:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
After a windows node is launched, a 'node' object is created by sending a request to API server.
    - Initially the node is in a Not-Ready state.
    - This request is then observed by the VPC resource controller and patches the 'node' object capacity with following: 
        "vpc.amazonaws.com/PrivateIPv4Address:  <Supported-number-of-ENIs>"
    - The kubelet then updates the node status to 'Ready'
> Windows nodes support one elastic network interface per node. The number of pods that you can run per Windows node is equal to the number of IP addresses available per elastic network interface for the node's instance type, minus one.

Windows pod provisioning workflow:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
After a pod is created by sending a request to API server, 
    The API server makes a call to the mutating webhook (vpc-admission-webhook)
        The webhook then identifies the pods with nodeSelector: kubernetes.io/os: windows.
        The webhook then patches the pod with the below limits and requests:
            Limits:
                vpc.amazonaws.com/PrivateIPv4Address:  1
            Requests:
                vpc.amazonaws.com/PrivateIPv4Address:  1
            
            The pod object is then persisted to ETCD. At this point the pod status is Pending.
                The scheduler then watches for pod objects that do not have a node assigned to them and assigns a node based on the allocated extended resource vpc.amazonaws.com/PrivateIPv4Address.

                Allocated resources for pod:
                Resource                              Requests    Limits
                --------                              --------    ------
                vpc.amazonaws.com/PrivateIPv4Address  1           1
                
                The VPC resource controller then checks for pods that have the required limits and requests.
                    When it finds a pod, it checks its warm pool and assigns an IP address to the pod, at which point CNI binary takes over and sets up pod networking.
                        Annotations: vpc.amazonaws.com/PrivateIPv4Address: 10.0.3.229/24
                    Kubelet then marks the pod as ready.

> vpc-admission-webhook is a mutating webhook.

Kubernetes Services:
~~~~~~~~~~~~~~~~~~~~
    - Service is an abstract way to expose an application running as an application within your kubernetes cluster.

Why services:
    - In kubernetes each pod has an internal IP address, but the pods in a deployment come and go and their IPs change.
    - So it does not help if you use pods' IP address to communicate with the application.
    - When you create a service to expose a set of pods, you get a static IP address that lasts for the life of the service, even if the backend pods are replaced. This makes services a very reliable feature to expose your application.

There are different types of services and the most commonly used ones are Cluster IP, NodePort and Loadbalancer type services.

Cluster IP:
    - A ClusterIP service is the default Kubernetes service.
    - When you create a service of type Cluster IP, only the applications within the cluster can access it. 
    - There is no external access. Having said that, if you do want to expose your Cluster IP service externally for any troubleshooting/debugging purpose or to provide access to any internal dashboards, you can use kubernetes proxy.
    - After starting the proxy, you can access the service using the kubernetes API over the proxy port. - /api/v1/proxy/namespaces/<NAMESPACE>/services/<SERVICE-NAME>:<PORT-NAME>/

NodePort:
    - A NodePort service is the most primitive way to get external traffic directly to your service. 
    - NodePort, as the name implies, opens a specific port on all the Nodes (the VMs), and any traffic that is sent to this port is forwarded to the service.
    - Some of the downsides to using this type of service are
        1. You can only have one service per port.
        2. You can only use the port range 30,000 - 32,767.
        3. If your Node IP changes, you also need to make changes accordingly.

LoadBalancer:
    - A Loadbalancer type service is the standard way to expose a service to the internet. Within AWS cloud to expose your application, your Loadbalancer choices are Classic LB, NLB or an ALB
    - Using the in-tree service controller you can only create a CLB or NLB. 
    - To be able to provision an ALB, you need to deploy AWS Loadbalancer Controller to your EKS Cluster, which takes care of creating an ALB for you whenever you create an Ingress Object.
    - With the latest version of the AWS Loadbalancer controller you can also provision an NLB. The type of Loadbalancer to provision when using the AWS LB Controller can specified by adding the respective annotations to the Ingress definition.

Services Quip: https://quip-amazon.com/R88mAEEAaCYK/02-Services-Ingress-on-EKS 

Ingress:
~~~~~~~~
Ingress exposes HTTP and HTTPS routes from outside the cluster to services within the cluster. Traffic routing is controlled by rules defined on the Ingress resource.
A request from outside first reaches the Loadbalancer managed by the ingress
    -> The traffic then gets to the Kubernetes Ingress itself where the routing rules are defined.
        -> Depending on the rule defined the traffic is forwarded to the respective service.
            -> The service then forwards the traffic to its endpoints, which are essentially your kubernetes pods where application is running.

    - Though it does the same job of a Loadbalancer type service, Ingress is actually not a type of service.
    - It sits in front of multiple services and acts as a smart router to direct traffic to the respective services.
    - Unlike services, Ingress gives you the ability to do path based and domain based routing to backend services.
    - The type of annotations you add to the Ingress definition typically defines the Loadbalancer properties like the listener port, the SSL certificate to use, backend protocol, routes etc.

External Traffic Policy: Default value is 'Cluster'
    - By default, the source IP seen in the 'target container' is not the original source IP of the client. 
    - Setting this property dictates if the service will route external traffic to the node locally or to cluster wide endpoints i,e to the pods running on the same node or to the pods running on other worker nodes too.
    - "Local" preserves the client source IP and avoids a second hop for 'LoadBalancer' and 'NodePort' type services, but has risks of potentially imbalanced traffic spreading. 
    - "Cluster" on the other hand does not preserve the client source IP and may cause a second hop to another node, but should have good overall load-spreading.
    - Unless specified, the default value is 'Cluster'.
    https://medium.com/pablo-perez/k8s-externaltrafficpolicy-local-or-cluster-40b259a19404 

AWS LoadBalancer Controller:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> The AWS Load Balancer Controller manages AWS Elastic Load Balancers for a Kubernetes cluster.
    - It creates an AWS Application Load Balancer (ALB) when you create a Kubernetes Ingress. 
    - An AWS Network Load Balancer (NLB) when you create a Kubernetes Service of type LoadBalancer.
> The loadbalancer controller pod runs as a deployment within the cluster.
> The LoadBalancer controller uses IAM Roles for Service Accounts to provide the controller pod with permissions to create/update/modify loadbalancer resources.

Once ingress is created a series of actions will be trigged by AWS LoadBalancer Controller:
   - Creates a SecurityGroup for the ALB.
   - Adds rules to the ALB SG.
   - Creates targetGroups to be assigned to LoadBalancer.
   - Creates a LoadBalancer - ALB/NLB based on the annotations specified.
   - Creates an ELB listener - the port on which load balancer will be listening on.
   - Adds listener rules to forward to the targetGroups (target groups in our case)
   - Create a custom resource called TargetGroupBinding which maintains target groups and worker node SG rules.
   - Authorize SG - Node's SG rule is modified to allow ingress from ELB SG.
   - Register targets to the TargetGroup.

Admission Controllers:
~~~~~~~~~~~~~~~~~~~~~~
An admission controller intercepts and processes requests to the Kubernetes API prior to persistence of the object, but after the request is authenticated and authorized.

These controllers are compiled and shipped into the kube-apiserver binary, and can only be enabled and configured by the cluster administrator using the --enable-admission-plugins and --admission-control-config-file flags. 

Webhooks:
~~~~~~~~~
Webhooks are a means to extend the functionality of admission controllers. You can extend and customize the Kubernetes API functionality, without adding complexity to its base code, by using webhooks. 

The Kubernetes API server will call a registered webhook, which is a rather standard interface. This makes admission controllers easy to integrate with any third-party code. 

You can define two types of admission webhooks, 
   i. validating admission webhook. - Pod security policy
  ii. mutating admission webhook. - vpc admission webhook - windows pods

Mutating admission webhooks are invoked first, and can modify objects sent to the API server to enforce custom defaults. 
After all object modifications are complete, and after the incoming object is validated by the API server, validating admission webhooks are invoked and can reject requests to enforce custom policies.

Large cluster deployment - what all best practices do we need to see from data plain?
- 
  Control Plane:
    - Select how the API server endpoint must Exposed (public or private endpoints.)
    - Enable logging.
    - Request service team to accommodate optimum instance types for Master and ETCD
    - Do not delete the master SG, Do not delete the ENI of the master.
  General guidance:
    - VPC CIDR must be able to accommodate the current estimate and must have space for future growth.
    - select the node instance based on the workloads.
    - optimize the **WARM_IP_TARGET and MINIMUM_IP_TARGET** to avoid API throttling.
    - make sure to use **limits and requests** for the pods.
    - Configure **kube-reserved and system-reserved** to ensure enough resources are always available for kubelet and system daemons like container runtime, ssh, cronjobs etc. 
    - use an **autoscaling mechanism to Scale DNS pods based on load** 
    - use conditional forwards in DNS ConfigMap.
    - use node-local dns to avoid dns throttling.
    - Cluster autoscaler
    - HPA.
    - VPA
    - are we going to use PV's ?
      - limits on volumes being AZ specific
    - Explain on Per instance Volume limits and avoid launching a lot of pods with PV on the same node. 
    - Configure PDBs.
  Security:
    - If there are multiple teams dealing with multiple namespaces?
      - use RBAC to restrict access.
    - Enable logging from the masters end.
    - use whitelisting of ip on the master. 
    - Use Security context, PSP, network policies to restrict privileges.
    - never run the workloads as root. 
    - never provide capabilities which have admin privileges. 
    - Avoid run pods on host network. 
    - Use KMS encryption for Volumes and secrets.
    - Use volume mounts over environment variables.

  - Backup:
    - Try to have version control enabled for manifest files and config files to be able to re-deploy resources if required. 

Zero Downtime Deployments:
~~~~~~~~~~~~~~~~~~~~~~~~~
https://broadcast.amazon.com/videos/203235

CoreDNS troubleshooting.
~~~~~~~~~~~~~~~~~~~~~~~

> Troubleshooting steps
Does kube-proxy talk to API server? Why? 

Taints and Tolerations:
~~~~~~~~~~~~~~~~~~~~~~~
    > These are used to repel the pods from nodes.
    > Taints are added to node using kubectl or can also be specified via the kubelt extra arguments.
    > For a node that has got taints added to it, to be able to schedule pods on it, the pods need to have the corresponding tolerations specified in its podSpec.

    Taints have a key, value and an effect specified in them. Valid options for effects are NoSchedule, PreferNoSchedule and NoExecute.
    - NoSchedule: effect indicates that without a valid toleration pods cannot be placed scheduled onto it.
    - PreferNoSchedule: effect indicates that the system will try to avoid placing a pod that does not tolerate the  
        taint on the node, but it is not a hard requirement.
    - NoExecute: effect indicates that the pod will be evicted from the node if it is already running on the node,   
        when the taint is applied. If it is not running then it will not be scheduled on it in the first place. The amount of time to wait before deciding to evict the pod form the node can be configured by specifying 'tolerationSeconds' property within the toleration on the podSpec.

Pod Disruption Budgets (PDB):
~~~~~~~~~~~~~~~~~~~~~~

PDBs are configured to increase application availability during application updates, infrastructure upgrades and  from frequent voluntary disruptions.

A PDB limits the number of Pods of a replica-set/deployment that are down simultaneously from voluntary disruptions.

A PDB specifies the number of replicas that an application can tolerate having, relative to how many it is intended to have. 

    For example, Generally a Deployment with .spec.replicas set to 5 is supposed to have 5 pods at any given time. 
    If its PDB allows for there to be 4 at a time, then a voluntary disruption of one (but not two) pods at a time is allowed.





