function add-HostEntry
{
    param([string] $ip, [string] $dns)

    $entry = "$ip $dns"

    $hostpath = "$env:windir\System32\drivers\etc\hosts"

    write-host "path $hostpath"
    foreach($e in gc $hostpath)
    {
        if($e -eq $entry)
        {
            write-host "Host entry $entry was already registered, hosts file won't be changed"
            return
        }
    }

    $lastline = gc $hostpath -raw | select -last 1

    if(-not (gc $hostpath -raw).EndsWith("`n"))
    {
        add-content $hostpath "" -Encoding Ascii
    }

    write-host "Adding entry $entry to hosts file"

    add-content $hostpath $entry -Encoding Ascii
}

function Set-CertificatePermission
{
    param
    (
        [Parameter(Position=1, Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$pfxThumbPrint,

        [Parameter(Position=2, Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$serviceAccount
    )

    $cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object -FilterScript { $PSItem.ThumbPrint -eq $pfxThumbPrint; };

    # Specify the user, the permissions and the permission type
    $permission = "$($serviceAccount)","Read,FullControl","Allow"
    $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission;

    # Location of the machine related keys
    $keyPath = $env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys\";
    $keyName = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName;
    $keyFullPath = $keyPath + $keyName;

    try
    {
        # Get the current acl of the private key
        # This is the line that fails!
        $acl = Get-Acl -Path $keyFullPath;

        # Add the new ace to the acl of the private key
        $acl.AddAccessRule($accessRule);

        # Write back the new acl
        Set-Acl -Path $keyFullPath -AclObject $acl;
    }
    catch
    {
        throw $_;
    }
}