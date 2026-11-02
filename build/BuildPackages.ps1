# Builds the three packages locally, as the Release workflow (.github/workflows/release.yml) does.
# Releases are published by that workflow, not from here; see developernotes.md.
# The assembly version comes from the latest tag (`git describe --tags`, build/PreBuild.targets.xml), so tag the commit first.
param(
    [string] [parameter(Mandatory = $true)] $version)

$ErrorActionPreference = "Stop"

write-host "Restoring nuget packages" -ForegroundColor Yellow
.\nuget.exe restore ..\src\dk.nita.saml20

foreach ($project in 'dk.nita.saml20', 'dk.nita.saml20.ext.audit.log4net', 'dk.nita.saml20.ext.sessionstore.sqlserver')
{
    write-host "Building nuget package $project" -ForegroundColor Yellow
    .\nuget.exe pack "..\src\dk.nita.saml20\$project\$project.csproj" -build -Version $version -Symbols -SymbolPackageFormat snupkg -Properties Configuration=Release
}
