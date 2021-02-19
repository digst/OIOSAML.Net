# Certificate generation

Certificates are issued using the following powershell

*   New-SelfSignedCertificate -DnsName "oiosaml-net.dk" -NotAfter "2030-01-01" -Provider "Microsoft Enhanced Cryptographic Provider v1.0"
*   New-SelfSignedCertificate -DnsName "oiosaml-demoidp.dk" -NotAfter "2030-01-01" -Provider "Microsoft Enhanced Cryptographic Provider v1.0"
*   New-SelfSignedCertificate -Subject "oiosaml test demoidp" -NotAfter "2030-01-01" -Provider "Microsoft Enhanced Cryptographic Provider v1.0"
*   New-SelfSignedCertificate -Subject "oiosaml test serviceprovider" -NotAfter "2030-01-01" -Provider "Microsoft Enhanced Cryptographic Provider v1.0"

# Creating a new OIOSAML .Net release

## Update documentation

Ensure documentation is updated with the changes, and that the release history is updated.

## Run integrationtests

Integration test must be performed on a test service provider. The latest integrationstest is available [here](https://digitaliser.dk/resource/3126701/artefact/IntegrationstestV1.7.pdf?artefact=true&PID=3126703)  

The test cases should be run using the test service provider https://oiosaml-net.dk:20002  

The following test cases must be run:

* IT-LOGON-1
* IT-SSO-1
* IT-SPSES-1
* IT-SLO-1
* IT-SLO-2
    * (Anden service provider findes på https://test-nemlog-in.dk/testportal/ (https://sp1.test-nemlog-in.dk/demo/)
* IT-SLO-3
* IT-TIM-1
* IT-TIM-2
* IT-LOG-1
* IT-FORCE-1
* IT-REPL-1

Følgende tests skal der verificeres at attributer korrekt gennemstilles, men det er den enkelte applikations ansvar at behandle

* IT-LOA-1
* IT-PRIV-1
* IT-PRIV-2
* IT-PRIV-3

Følgende tests er ikke relevant for OIOSAML.net komponenten:

* IT-USER-1
* IT-CDC-1
* IT-ATTQ-1
* IT-SIGN-1

## Build the packages

* Run the BuildPackages.ps1, setting version to a proper version number, e.g 1.0.0 and assemblyVersion to a proper version number, e.g 1.0.0.0\. Use 1.0.0-alpha, 1.00-beta, etc. as version number to make a prerelease
* Verify the packages looks good and are ready to publish
* Ensure API key to digitaliseringsstyrelsen's nuget account is installed on your machine
* Push packages to NuGet by running BuildPackages.ps1 with the switch -pushPackages
* Add a tag in Git corresponding to the release

## Creating the new resource on digitaliser.dk

* Login on digitaliser.dk and go to the newest version of the ressource (should be https://www.digitaliser.dk/group/42063/resources)
* Choose Funktioner and click on "Opret ny version"
* Change the metadata of the ressource accordingly, remember adding link to SVN and the published Nuget packages
* Publish the new version when ready

## Change the frontpage of the group

* Login on digitaliser.dk and go to the oiosaml group (http://digitaliser.dk/group/42063)
* Find the old promotion on the grouppage and remove it.
* Find the new promotion on the grouppage by using the ID from the URL of the page showing the new version.
