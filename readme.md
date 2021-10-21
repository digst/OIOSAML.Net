# Nota bene

Please note that the tagged version in Git does not follow the OIO SAML profile version. The correlation is described below
*    OIO SAML 2.0.9: Newest NuGet release: 2.0.6
*    OIO SAML 2.1.0: Newest NuGet release: 2.0.6 (only metadata changes required)
*    OIO SAML 3.0.2: Newest NuGet release: 3.0.1

See content and changes of releases in [release notes](RELEASE_NOTES.md).

# Getting started with OIOSAML.Net

This is the codebase that the OIOSAML.Net components are built from.

## Resource links

*   [Project maintenance](https://digitaliser.dk/group/42063)
*   [Nuget packages (prefixed dk.nita.saml20)](https://www.nuget.org/profiles/Digitaliseringsstyrelsen)
*   [Code repository](https://github.com/digst/OIOSAML.Net)

## Repository content

*   **build**: Contains script to create and publish NuGet packages
*   **certificates**: Certificates used for getting the demo sample up and running
*   **setup**: Setup scripts used for getting demo sample up and running
*   **src**: source code for the OIOSAML.Net framework
*   **developer notes.html**: Information relevant for developers of OIOSAML.Net
*   **Net SAML2 Service Provider Framework.docx**: General documentation on how to use OIOSAML.Net
*   **readme.html**: This file

## Getting started

The source code contains everything you need to get a demonstration environment up and running, federating with your own local Identity Provider, as well as directly against NemLog-in.

_The full documentation on the project is available in the document 'Net SAML2 Service Provider Framework.docx'_

For a quick setup, you must do the following:

*   Run the script 'setup\setup_prerequisites.ps1' from an elevated powershell. This installs all required certificates and performs sslcert bindings to be able to host local websites using https
*   Open the solution 'dk.nita.saml20.sln' in Visual Studio 2019 (Elevated mode) and build it (if you get errors on external dependencies, ensure nuget packages are being restored)
*   Set the projects 'IdentityProviderDemo' and 'WebsiteDemo' as startup projects by right-clicking solution, select 'properties', selecting 'Multiple start projects'
*   For the web projects, you must manually set the 'Start URL' that IIS express uses. You do this by:
    *   right click project 'IdentityProviderDemo', select 'properties', select the tab 'Web', alter the 'Start Action' to the radio button 'Start URL', specifying 'https://oiosaml-demoidp.dk:20001'
    *   right click project 'WebsiteDemo', select 'properties', select the tab 'Web', alter the 'Start Action' to the radio button 'Start URL', specifying 'https://oiosaml-net.dk:20002'
*   Run the solution which should start IIS express for the two websites

This should start two browser windows, one for the demo idp ('IdentityProviderDemo'), and one for the service provider ('WebsiteDemo').  

On the service provider you should now be able to log in using either the demo idp or NemLog-in, by selecting the identity provider in the list of identity providers:  

* If you choose NemLog-in, you must use an certificate employee certificate from the [NemLog-In testportal](https://test-nemlog-in.dk/testportal/)  
* If you choose the local demo idp, you log in with a username/password with one of the users listed in the web.config file for the demo idp under the 'demoIdp' section
