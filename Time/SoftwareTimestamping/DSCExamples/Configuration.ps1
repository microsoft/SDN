Configuration TimeStamp {

    Import-DscResource -ModuleName SoftwareTimestamping

    SoftwareTimestamping 'iWARP-40G-1 - Timestamping Config' {
        Ensure = 'Present'
        NetAdapterName = 'iWARP-40G-1'
        TimestampValue = 5
    }

    SoftwareTimestamping 'iWARP-40G-2 - Timestamping Config' {
        Ensure = 'Present'
        NetAdapterName = 'iWARP-40G-2'
        TimestampValue = 5
    }

    SoftwareTimestamping 'NIC1 - Timestamping Config' {
        Ensure = 'Absent'
        NetAdapterName = 'NIC1'
    }

    SoftwareTimestamping 'vEthernet (Tester) - Timestamping Config' {
        Ensure = 'Absent'
        NetAdapterName = 'vEthernet (Tester)'
    }
}

TimeStamp -OutputPath c:\temp\
Start-DscConfiguration -Path c:\temp -Verbose -Wait -Force