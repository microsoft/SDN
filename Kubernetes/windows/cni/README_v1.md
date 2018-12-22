# ADD Cases
1.	Pause (Infra) Container Get Created first. 
2.	CRI calls CNI to add an Endpoint to the Pause (Infra) Container.  
    •	[CNI]   ADD Infra [containerId:<infra container id> netns:none]
    •	[CNI] Find if endpoint exists, if yes, return the endpoint info.
    •	[CNI] If not, Creates Endpoint via HNS  (Only place where endpoint is to be created. The netns would be empty or none.). 
    •	[CNI] Hot adds the endpoint to the Pause (Infra) Container by calling HCS. 
        o	This may fail sometime, if the container is not running anymore. 
        o	This can happen if the container is unstable. 
        o	Cleanup the endpoint on failure, since it is created here.
3.	CRI creates Workload Container.  
4.	CRI calls CNI to hotadd the endpoint to the workload container by calling with a Container (netns would be container:<infracontainerid>). -> this call is only for Windows
    •	[CNI] ADD Workload [containerId:<workload container id> netns:container:<infra container id>]
    •	[CNI] At this point the endpoint should already exist, if it doesn’t return error.  Kubelet may be in the process of cleaning up this POD. Never create endpoint here.
    •	[CNI] Hot adds the endpoint to the Workload Container by calling HCS. If hot add fails, do not attempt to cleanup the endpoint. Just return error

# DEL Cases
5.	CRI Calls CNI to cleanup workload containers endpoint
    •	[CNI] DEL ADD Workload [containerId:<workload container id> netns:container:<infra container id>]
    •	[CNI] Find the endpoint & call Hot Remove. Do not delete the endpoint here as workload doesn’t own it. Do not return failure on error, as this is a cleanup code
6.	CRI deletes the workload container
7.	CRI Calls CNI to cleanup Infra container endpoint
    •	[CNI]  DEL Infra [containerId:<infra container id> netns:none]
    •	[CNI] Find the endpoint & call Hot Remove. If no endpoint is found, do not return failure on error, as this is a cleanup code
    •	[CNI] Delete the endpoint. do not return failure on error, as this is a cleanup code
    •	[CNI] Free up the IP

# Note:
    Always return error on ADD cases
    On DEL cases, try to not throw error & make sure we cleanup IP Reservations & Endpoints.
