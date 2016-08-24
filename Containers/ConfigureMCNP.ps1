# Run this script on the Hyper-V Host which is hosting Container Host (Tenant) VMs

REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\ProxiedServices\c79d8d8d-bbb4-42ea-8a8f-a492efc40a94" /v "ServerAddress" /t REG_SZ /d localhost /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\ProxiedServices\c79d8d8d-bbb4-42ea-8a8f-a492efc40a94" /v "ServiceName" /t REG_SZ /d mds /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\ProxiedServices\c79d8d8d-bbb4-42ea-8a8f-a492efc40a94" /v "ServerPort" /t REG_DWORD /d 6642 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\ProxiedServices\c79d8d8d-bbb4-42ea-8a8f-a492efc40a94" /v "ProxyListeningPort" /t REG_DWORD /d 6642 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\ProxiedServices\c79d8d8d-bbb4-42ea-8a8f-a492efc40a94" /v "ProxyListeningAddress" /t REG_SZ /d 0.0.0.0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\ProxiedServices\c79d8d8d-bbb4-42ea-8a8f-a492efc40a94" /v "ProxyProtocol" /t REG_SZ /d HttpUriPrefix /f


# VFP Policy/NCHostAgent registry 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\MetadataServer" /v "Port" /t REG_DWORD /d 6642 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\MetadataServer" /v "ProxyPort" /t REG_DWORD /d 6642 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\MetadataServer" /v "IP" /t REG_SZ /d 169.254.169.254 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\MetadataServer" /v "MAC" /t REG_SZ /d 22-22-22-22-22-22 /f


REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\NdResponder" /v "MetadataServer" /t REG_MULTI_SZ /d 169.254.169.254\022-22-22-22-22-22 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" /v "MetadataServerPort" /t REG_DWORD /d 6642 /f

Netsh advfirewall firewall add rule name="Open Port 6642" dir=in action=allow protocol=TCP localport=6642
Netsh advfirewall firewall add rule name="Open Port 6642" dir=out action=allow protocol=TCP localport=6642



Restart-service nchostagent
