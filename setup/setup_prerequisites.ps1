#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Push-Location

set-location $PSScriptRoot

. .\functions.ps1

$certpassword = ConvertTo-SecureString -String "test1234" -AsPlainText -Force

write-host "Installing demoidp ssl certificate"
$demoIdpSslcertificate = Import-PfxCertificate '..\certificates\demoidp ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
$demoIdpSslcertificate = Import-PfxCertificate '..\certificates\demoidp ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople
write-host "Installed demo idp ssl certificate $($sslcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"

write-host "Installing demoidp ssl certificate"
$serviceProviderSslcertificate = Import-PfxCertificate '..\certificates\serviceprovider ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
$serviceProviderSslcertificate = Import-PfxCertificate '..\certificates\serviceprovider ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople
write-host "Installed demo idp ssl certificate $($sslcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"

write-host "Installing demoidp's signing certificate"
$demoidpcertificate = Import-PfxCertificate '..\certificates\demoidp.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
$demoidpcertificate = Import-PfxCertificate '..\certificates\demoidp.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople
write-host "Installed demoidp's signing certificate $($demoidpcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"
write-host "This certificate must be configured as the signing certificate for the demoidp"

write-host "Installing demoidp's expired signing certificate"
$demoidpexpiredcertificate = Import-PfxCertificate '..\certificates\demoidp-expired.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
$demoidpexpiredcertificate = Import-PfxCertificate '..\certificates\demoidp-expired.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople
write-host "Installed demoidp's expired signing certificate $($demoidpexpiredcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"
write-host "This certificate is automatically configured as one of the signing certificates for the demoidp"

write-host "Installing serviceprovider's signing certificate"
$serviceprovidercertificate = Import-PfxCertificate '..\certificates\serviceprovider.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
$serviceprovidercertificate = Import-PfxCertificate '..\certificates\serviceprovider.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople
write-host "Installed serviceprovider's signing certificate $($serviceprovidercertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"
write-host "This certificate is used by the demo website (service provider) as its current signing certificate"

write-host "Installing serviceprovider's expired signing certificate"
$serviceproviderexpiredcertificate = Import-PfxCertificate '..\certificates\serviceprovider-expired.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
$serviceproviderexpiredcertificate = Import-PfxCertificate '..\certificates\serviceprovider-expired.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople
write-host "Installed serviceprovider's expired signing certificate $($serviceproviderexpiredcertificate.Thumbprint) in LocalMachine\My and LocalMachine\TrustedPeople. This ensures the certificate is trusted on your machine and browser"
write-host "This certificate is used by the demo website (service provider) as one of its signing certificates"

#If you need to redo sslcert binding, the following statements will delete previously creates ones
#"http delete sslcert ipport=0.0.0.0:20001" | netsh
#"http delete sslcert ipport=0.0.0.0:20002" | netsh

write-host "Registering demo idp ssl certificate $($demoIdpSslcertificate.Thumbprint) for SSL bindings for demo sites"
"http add sslcert ipport=0.0.0.0:20001 certhash=$($demoIdpSslcertificate.Thumbprint) appid={$([Guid]::NewGuid().ToString().ToUpper())}" | netsh
write-host "Registering service provider ssl certificate $($serviceProviderSslcertificate.Thumbprint) for SSL bindings for demo sites"
"http add sslcert ipport=0.0.0.0:20002 certhash=$($serviceProviderSslcertificate.Thumbprint) appid={$([Guid]::NewGuid().ToString().ToUpper())}" | netsh

write-host "If you want to re-run the sslcert bindings, you must manually delete the sslcert's (look inside this script for guidance)"

$username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
write-host "Setting private key access for your identity $username on the demo idp signing certificate $($demoIdpSslcertificate.Thumbprint) in the certificate store"
Set-CertificatePermission $demoidpcertificate.Thumbprint $username
write-host "Setting private key access for your identity $username on the service provider signing certificate $($serviceprovidercertificate.Thumbprint) in the certificate store"
Set-CertificatePermission $serviceprovidercertificate.Thumbprint $username
write-host "Setting private key access for your identity $username on the demo idp signing expired certificate $($demoidpexpiredcertificate.Thumbprint) in the certificate store"
Set-CertificatePermission $demoidpexpiredcertificate.Thumbprint $username
write-host "Setting private key access for your identity $username on the service provider signing expired certificate $($serviceproviderexpiredcertificate.Thumbprint) in the certificate store"
Set-CertificatePermission $serviceproviderexpiredcertificate.Thumbprint $username

add-HostEntry "127.0.0.1" "oiosaml-demoidp.dk"
add-HostEntry "127.0.0.1" "oiosaml-net.dk"

write-host "Setup completed!"
write-host "You should now open the solution in Visual Studio, build it and run it!"

Pop-Location