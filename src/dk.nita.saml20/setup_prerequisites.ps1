#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Push-Location

set-location $PSScriptRoot

. .\functions.ps1

$certpassword = ConvertTo-SecureString -String "test1234" -AsPlainText -Force

write-host "Installing ssl certificate"
$sslcertificate = Import-PfxCertificate 'certificates\ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
$sslcertificate = Import-PfxCertificate 'certificates\ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople
write-host "Installed ssl certificate $($sslcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"

write-host "Installing demoidp's signing certificate"
$demoidpcertificate = Import-PfxCertificate 'certificates\demoidp.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
$demoidpcertificate = Import-PfxCertificate 'certificates\demoidp.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople
write-host "Installed demoidp's signing certificate $($demoidpcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"
write-host "This certificate must be configured as the signing certificate for the demoidp"

write-host "Installing serviceprovider's signing certificate"
$serviceprovidercertificate = Import-PfxCertificate 'certificates\serviceprovider.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
$serviceprovidercertificate = Import-PfxCertificate 'certificates\serviceprovider.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople
write-host "Installed serviceprovider's signing certificate $($serviceprovidercertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"
write-host "This certificate is used by the demo website (service provider) as its signing certificate"

#If you need to redo sslcert binding, the following statements will delete previously creates ones
#"http delete sslcert ipport=0.0.0.0:20001" | netsh
#"http delete sslcert ipport=0.0.0.0:20002" | netsh

write-host "Registering ssl certificate $($sslcertificate.Thumbprint) for SSL bindings for demo sites"
write-host "If you want to re-run this script, you must manually delete the sslcert's (look inside this script for guidance)"
"http add sslcert ipport=0.0.0.0:20001 certhash=$($sslcertificate.Thumbprint) appid={$([Guid]::NewGuid().ToString().ToUpper())}" | netsh
"http add sslcert ipport=0.0.0.0:20002 certhash=$($sslcertificate.Thumbprint) appid={$([Guid]::NewGuid().ToString().ToUpper())}" | netsh

$username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Set-CertificatePermission $sslcertificate.Thumbprint $username

write-host "Setup completed!"
write-host "You should now open the solution in Visual Studio, build it and run it!"

Pop-Location