
$win32PInvoke = @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct WSAData
{
    public Int16 version;
    public Int16 highVersion;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
    public String description;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
    public String systemStatus;

    public Int16 maxSockets;
    public Int16 maxUdpDg;
    public IntPtr vendorInfo;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct INET_PORT_RANGE {
    public UInt16 startPort;
    public UInt16 numberOfPorts;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct INET_PORT_RESERVATION_TOKEN{
    UInt64 token;
} 

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct INET_PORT_RESERVATION_INSTANCE {
    public INET_PORT_RANGE reservation;
    public INET_PORT_RESERVATION_TOKEN token;
} 

public enum ADDRESS_FAMILIES : ushort
{
    AF_INET = 2,
}

public enum SOCKET_TYPE : ushort
{
    SOCK_NONE = 0,
}

public enum PROTOCOL : ushort
{
    IPPROTO_IP = 0,
}

public enum IOCTL_CODE : uint
{
    SIO_ACQUIRE_PORT_RESERVATION = 2550136932,
}

[DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError=true)]
public static extern Int32 WSAStartup(
    Int16 wVersionRequested, 
    out WSAData wsaData);

[DllImport("ws2_32.dll",CharSet = CharSet.Unicode, SetLastError=true)]
public static extern Int32 WSACleanup();

[DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
public static extern IntPtr socket(
    ADDRESS_FAMILIES af, 
    SOCKET_TYPE socket_type, 
    PROTOCOL protocol);

[DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int closesocket(
    IntPtr s);

[DllImport("Ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int WSAIoctl(
    IntPtr s, 
    IOCTL_CODE dwIoControlCode,
    ref INET_PORT_RANGE lpvInBuffer, 
    int cbInBuffer,
    out INET_PORT_RESERVATION_INSTANCE lpvOutBuffer, 
    int cbOutBuffer,
    ref int lpcbBytesReturned,
    IntPtr lpOverlapped, 
    IntPtr lpCompletionRoutine);

[DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError=true)]
public static extern UInt16 ntohs(
    UInt16 netshort);

[DllImport("ws2_32.dll", CharSet = CharSet.Unicode)]
public static extern Int32 WSAGetLastError();
'@

Add-Type -MemberDefinition $win32PInvoke `
    -Name Win32Calls -Namespace ws232 `
    -Using System.Text

[ws232.Win32Calls+WSAData] $WSAData = New-Object ws232.Win32Calls+WSAData
if ([ws232.Win32Calls]::WSAStartup(0x0202, [Ref] $WSAData) -ne 0) { throw "WSAStartup failed" }

[ws232.Win32Calls+ADDRESS_FAMILIES] $iFamily = [Int32][ws232.Win32Calls+ADDRESS_FAMILIES]::AF_INET;
[ws232.Win32Calls+SOCKET_TYPE] $iType = [ws232.Win32Calls+SOCKET_TYPE]::SOCK_NONE;
[ws232.Win32Calls+PROTOCOL] $iProtocol = [ws232.Win32Calls+PROTOCOL]::IPPROTO_IP;

$socket = [ws232.Win32Calls]::socket($iFamily, $iType, $iProtocol)

if ($socket -eq -1) { throw "Failed to open a socket" }

[ws232.Win32Calls+INET_PORT_RANGE] $portRange = New-Object ws232.Win32Calls+INET_PORT_RANGE
[ws232.Win32Calls+INET_PORT_RESERVATION_INSTANCE] $portRes = New-Object ws232.Win32Calls+INET_PORT_RESERVATION_INSTANCE
[System.Int32] $bytesReturned = 0
$portRange.numberOfPorts = 64

$successCount = 0

for ( $i = 0; $i -lt 10 ; $i++) {
    if ([ws232.Win32Calls]::WSAIoctl(
        $socket, 
        [ws232.Win32Calls+IOCTL_CODE]::SIO_ACQUIRE_PORT_RESERVATION, 
        [ref] $portRange, 
        [System.Runtime.InteropServices.Marshal]::SizeOf($portRange),
        [ref] $portRes,
        [System.Runtime.InteropServices.Marshal]::SizeOf($portRes),
        [ref] $bytesReturned,
        [IntPtr]::Zero,
        [IntPtr]::Zero) -eq 0) {

        $successCount++
    }
}

if ($successCount -eq 10) {
    Write-Output "Successfully reserved 10 ranges of 64 ports"
} else {
    Write-Output "Couldn't reserve more than $($successCount) ranges of 64 ports"
}

if ([ws232.Win32Calls]::closesocket($socket) -ne 0) { throw "Failed to close the socket" }
if ([ws232.Win32Calls]::WSACleanup() -ne 0) { throw "Failed to perform WSACleanup" }

