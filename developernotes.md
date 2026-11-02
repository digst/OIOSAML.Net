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

Integration test must be performed on a test service provider. The test cases are described in NemLog-in's [Integrationstest ved tilslutning til NemLog-in](https://cms.nemlog-in.dk/media/psknz1el/integrationstest-ved-tilslutning-til-nemlog-in.pdf)  

The test cases should be run using the test service provider https://localhost:20002  

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

## Release

Releases are tags on `main`, without a `v` (e.g. `3.1.0`, as the earlier releases); the assembly version is read from the tag by `git describe`.

1. Update `RELEASE_NOTES.md`, including "Upgrading from" notes for behaviour integrators must act on, and merge it to `main`.
2. Run the integration tests above against DevTest4.
3. Optional: run the **Release** workflow by hand (Actions → Release → Run workflow) on `main` and inspect the `packages` artifact; a run by hand never publishes.
4. Tag the release commit on `main` and push the tag: `git tag 3.1.0 && git push origin 3.1.0`.
5. The **Release** workflow builds, tests and packs the three packages, then waits for approval in the `nuget` environment. After approval it publishes them to nuget.org by Trusted Publishing; no API key is stored anywhere.
6. Create a GitHub release for the tag with the release notes.

`build/BuildPackages.ps1 -version <version>` builds the same packages locally.

### One-time setup for Trusted Publishing

- On nuget.org, an owner of the Digitaliseringsstyrelsen account adds a Trusted Publishing policy: repository owner `digst`, repository `OIOSAML.Net`, workflow `release.yml`, environment `nuget`.
- In the repository settings: an environment `nuget` with required reviewers, and a repository variable `NUGET_USER` with the nuget.org user name of the policy owner.
