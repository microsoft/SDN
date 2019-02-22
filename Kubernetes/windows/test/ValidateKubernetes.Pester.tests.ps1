<#
.DESCRIPTION
    This script validates basic connectivity for Windows nodes in a Kubernetes cluster. 
    Assumes the cluster has no other services/pods deployed besides kube-system
#>

import-module "$PSScriptRoot\ValidateKubernetesHelper.psm1"

Describe 'Kubernetes Prerequisites' {
    
    Context 'Checking Docker images' {
        It "should have nanoserver image" {
            docker images | findstr nanoserver | Should Not BeNullOrEmpty
        }
        It "should have windowservercore image" {
            docker images | findstr windowsservercore | Should Not BeNullOrEmpty
        }
    }

    Context 'Checking Kubernetes Binaries are running' {
        It 'kubelet.exe is running' {
            get-process -Name 'kubelet' | Should be $true
        }
        It 'kube-proxy.exe is running' {
            get-process -Name 'kube-proxy'| Should be $true
        }
        It 'flanneld.exe is running' {
            get-process -Name 'flanneld' | Should be $true
        }
    }
}

Describe 'Basic Connectivity Tests' {
    Context 'Windows Connectivity' {
        BeforeAll {
            kubectl apply -f https://raw.githubusercontent.com/Microsoft/SDN/e1b7c4f59b8fa304db45494c1dcfd4c3cd77b531/Kubernetes/flannel/l2bridge/manifests/simpleweb.yml
            kubectl scale deployment win-webserver --replicas=4
            sleep -Seconds 30

            $workloadContainers = GetContainers
            $localContainers = GetContainers -PodLocation Local
            $remoteContainers = GetContainers -PodLocation Remote

            $serviceVIP = (kubectl get services -o json | ConvertFrom-Json).items[1].spec.clusterIP
            $nodePort = (kubectl get services -o json | ConvertFrom-Json).items[1].spec.ports.nodePort
        }
        AfterAll {
            C:\k\kubectl.exe delete deployment win-webserver
            C:\k\kubectl.exe delete service win-webserver 
        }
    
        It 'should have more than 1 local container' {
            $localContainers.count | Should BeGreaterThan 1
        }
        It 'should have at least 1 remote container' {
            $remoteContainers.count | Should BeGreaterThan 0
        }
        It 'Containers have correct IP' {
           foreach ($container in $workloadContainers)
            {
                Write-Host "Checking $($container.Name) has IP address $($container.IPAddress)"
                $container.IPAddress -eq (GetContainerIPv4Address -containerName $container.Name) | Should be $true
            }
        }
        It 'External connectivity' {
            foreach ($container in $workloadContainers)
            {
		        Write-Host "Testing from $($container.Name) $($container.IPAddress)"
                TestConnectivity -containerName $container.Name
            }
        }
        It 'Service VIP Access from containers' {
            foreach ($container in $workloadContainers)
            {
                Write-Host "Testing service VIP ${serviceVIP} from ${container.Name} ${container.IPAddress}"
                TestConnectivity -containerName $container.Name -remoteHost $serviceVIP
            }
        }
        It 'Local containers to local host connectivity' {
            $managementIP = WaitForManagementIP 
            foreach ($container in $localContainers)
            {
                PingTest -containerName $container.Name -destination $managementIP
            }
        }
        It 'Local host to local pod connectivity' {
            foreach ($container in $localContainers)
            {
                PingTest -destination $container.IPAddress -fromHost
            }
        }
        It 'Local pod connectivity' {
            foreach ($container1 in $localContainers)
            {
                foreach ($container2 in $localContainers)
                {
                    if ($container1.Name -ne $container2.Name) {
                        PingTest -containerName $container1.Name -destination $container2.IPAddress
                    }
                }
            }
        } 
        It 'Remote pod connectivity' {
            foreach ($container1 in $localContainers)
            {
                foreach ($container2 in $remoteContainers)
                {
                    PingTest -containerName $container1.Name -destination $container2.IPAddress
                }
            }
        } 
        It 'Node port access from remote host' {
            foreach ($container1 in $localContainers)
            {
                foreach ($container2 in $remoteContainers)
                {
                    TestConnectivity -remoteHost $container2.HostIP -port $nodePort -fromHost
                }
            }
        }
    }
} 