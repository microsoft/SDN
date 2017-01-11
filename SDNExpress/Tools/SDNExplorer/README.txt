Copy CertHelpers.psm1, NetworkControllerRESTWrappers.psm1, NetworkControllerWorkloadHelpers.psm1 and SDNExploree.ps1 to local folder.
From same folder run SDNExplorer.ps1 with below parameters:-
    NCIP - pass either network controller rest ip address or network controller restname. Make sure you pass same restname as of mentioned in rest certificate.
    NCCredential -  Optionally, pass System.Management.Automation.PSCredential if network controller is configured with Kerberos authentication.
    EnableMultiWindow - Don't change this parameter, it is for debugging purpose.   
