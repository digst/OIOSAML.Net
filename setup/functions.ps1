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

    if ($null -eq $cert)
    {
        throw "Certificate with thumbprint $pfxThumbPrint was not found in Cert:\LocalMachine\My";
    }

    # Specify the user, the permissions and the permission type
    $permission = "$($serviceAccount)","Read,FullControl","Allow"
    $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission;

    # Resolve the private key file in a provider-agnostic way so this works for both modern CNG keys
    # and legacy CryptoAPI (CSP) keys. Depending on how the certificate was imported, the key may be
    # stored under CNG (Microsoft\Crypto\Keys) or legacy CSP (Microsoft\Crypto\RSA\MachineKeys).
    # The old code used $cert.PrivateKey.CspKeyContainerInfo directly, which throws for CNG-stored keys.
    # Collect every candidate location and apply the ACL to whichever file actually exists.
    $candidateFiles = New-Object System.Collections.Generic.List[string];

    # CNG keys: Microsoft\Crypto\Keys, container file name = CngKey.UniqueName
    try
    {
        $cngRsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert);
        if ($cngRsa -is [System.Security.Cryptography.RSACng] -and -not [string]::IsNullOrEmpty($cngRsa.Key.UniqueName))
        {
            $candidateFiles.Add($env:ProgramData + "\Microsoft\Crypto\Keys\" + $cngRsa.Key.UniqueName);
        }
    }
    catch { }

    # Legacy CSP keys: Microsoft\Crypto\RSA\MachineKeys, container file name = UniqueKeyContainerName
    try
    {
        $cspRsa = $cert.PrivateKey;
        if ($null -ne $cspRsa -and $null -ne $cspRsa.CspKeyContainerInfo -and -not [string]::IsNullOrEmpty($cspRsa.CspKeyContainerInfo.UniqueKeyContainerName))
        {
            $candidateFiles.Add($env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys\" + $cspRsa.CspKeyContainerInfo.UniqueKeyContainerName);
        }
    }
    catch { }

    $applied = $false;
    foreach ($keyFullPath in ($candidateFiles | Select-Object -Unique))
    {
        if (Test-Path -Path $keyFullPath)
        {
            $acl = Get-Acl -Path $keyFullPath;
            $acl.AddAccessRule($accessRule);
            Set-Acl -Path $keyFullPath -AclObject $acl;
            $applied = $true;
        }
    }

    if (-not $applied)
    {
        throw "Could not locate the private key file for certificate $pfxThumbPrint (checked both the CNG and CSP key stores). The certificate's key provider metadata may be inconsistent - re-import the certificate cleanly.";
    }
}