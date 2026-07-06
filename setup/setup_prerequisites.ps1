#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Push-Location

set-location $PSScriptRoot

. .\functions.ps1

$certpassword = ConvertTo-SecureString -String "test1234" -AsPlainText -Force
$certpassword2  = ConvertTo-SecureString -String "Test1234" -AsPlainText -Force

write-host "Installing demoidp ssl certificate"
$demoIdpSslcertificate = Import-PfxCertificate '..\certificates\demoidp ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My -Exportable
$demoIdpSslcertificate = Import-PfxCertificate '..\certificates\demoidp ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople -Exportable
write-host "Installed demo idp ssl certificate $($demoIdpSslcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"

write-host "Installing demoidp's signing certificate"
$demoidpcertificate = Import-PfxCertificate '..\certificates\demoidp.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My -Exportable
$demoidpcertificate = Import-PfxCertificate '..\certificates\demoidp.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople -Exportable
write-host "Installed demoidp's signing certificate $($demoidpcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"
write-host "This certificate must be configured as the signing certificate for the demoidp"

write-host "Installing demoidp's expired signing certificate"
$demoidpexpiredcertificate = Import-PfxCertificate '..\certificates\demoidp-expired.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My -Exportable
$demoidpexpiredcertificate = Import-PfxCertificate '..\certificates\demoidp-expired.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople -Exportable
write-host "Installed demoidp's expired signing certificate $($demoidpexpiredcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"
write-host "This certificate is automatically configured as one of the signing certificates for the demoidp"

write-host "Installing serviceprovider's signing certificate"
$serviceprovidercertificate = Import-PfxCertificate '..\certificates\serviceprovider.p12' -Password $certpassword2 -CertStoreLocation Cert:\LocalMachine\My -Exportable
$serviceprovidercertificate = Import-PfxCertificate '..\certificates\serviceprovider.p12' -Password $certpassword2 -CertStoreLocation Cert:\LocalMachine\TrustedPeople -Exportable
write-host "Installed serviceprovider's signing certificate $($serviceprovidercertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"
write-host "This certificate is used by the demo website (service provider) as its current signing certificate"

#If you need to redo sslcert binding, the following statements will delete previously creates ones
#"http delete sslcert ipport=0.0.0.0:20001" | netsh
#"http delete sslcert ipport=0.0.0.0:20002" | netsh

write-host "Registering demo idp ssl certificate $($demoIdpSslcertificate.Thumbprint) for SSL bindings for demo sites"
"http add sslcert ipport=0.0.0.0:20001 certhash=$($demoIdpSslcertificate.Thumbprint) appid={$([Guid]::NewGuid().ToString().ToUpper())}" | netsh
# The service provider demo runs on https://localhost:20002. Bind the machine's localhost developer
# certificate (e.g. the IIS Express Development Certificate) to that port instead of a project-specific
# SSL certificate - it matches 'localhost' (no name-mismatch warning) and is already trusted.
$localhostDevCert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.FriendlyName -eq 'IIS Express Development Certificate' -or $_.Subject -eq 'CN=localhost' } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if ($null -eq $localhostDevCert)
{
    write-host "No localhost developer certificate found in Cert:\LocalMachine\My - creating a self-signed one"
    $localhostDevCert = New-SelfSignedCertificate `
        -Type SSLServerAuthentication `
        -DnsName "localhost" `
        -FriendlyName "OIOSAML demo localhost developer certificate" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -NotAfter (Get-Date).AddYears(5) `
        -KeyExportPolicy Exportable

    # A self-signed certificate is its own root, so add it to Trusted Root so browsers trust https://localhost.
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $rootStore.Open("ReadWrite")
    $rootStore.Add($localhostDevCert)
    $rootStore.Close()
    write-host "Created and trusted self-signed localhost certificate $($localhostDevCert.Thumbprint)"
}
write-host "Registering localhost developer certificate $($localhostDevCert.Thumbprint) for the SSL binding on port 20002"
"http add sslcert ipport=0.0.0.0:20002 certhash=$($localhostDevCert.Thumbprint) appid={$([Guid]::NewGuid().ToString().ToUpper())}" | netsh

write-host "If you want to re-run the sslcert bindings, you must manually delete the sslcert's (look inside this script for guidance)"

$username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
write-host "Setting private key access for your identity $username on the demo idp signing certificate $($demoIdpSslcertificate.Thumbprint) in the certificate store"
Set-CertificatePermission $demoidpcertificate.Thumbprint $username
write-host "Setting private key access for your identity $username on the service provider signing certificate $($serviceprovidercertificate.Thumbprint) in the certificate store"
Set-CertificatePermission $serviceprovidercertificate.Thumbprint $username
write-host "Setting private key access for your identity $username on the demo idp signing expired certificate $($demoidpexpiredcertificate.Thumbprint) in the certificate store"
Set-CertificatePermission $demoidpexpiredcertificate.Thumbprint $username

add-HostEntry "127.0.0.1" "oiosaml-demoidp.dk"

write-host "Setup completed!"
write-host "You should now open the solution in Visual Studio, build it and run it!"

Pop-Location