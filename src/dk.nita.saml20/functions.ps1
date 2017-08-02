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