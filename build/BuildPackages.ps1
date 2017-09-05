param([string] [parameter(Mandatory = $true)] $version, [switch] $pushPackages)

$ErrorActionPreference = "Stop"

$msbuildpath = "C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe"

if(!(test-path $msbuildpath))
{
    write-host "Could not find msbuild.exe at $msbuildpath"
    return
}

if($pushPackages.IsPresent)
{
    write-host "pushing package dk.nita.saml20" -ForegroundColor Yellow
    .\nuget.exe push $("dk.nita.saml20.$version.nupkg")

    write-host "pushing package dk.nita.saml20.ext.audit.log4net" -ForegroundColor Yellow
    .\nuget.exe push $("dk.nita.saml20.ext.audit.log4net.$version.nupkg")
    
    write-host "pushing package dk.nita.saml20.ext.sessionstore.sqlserver" -ForegroundColor Yellow
    .\nuget.exe push $("dk.nita.saml20.ext.sessionstore.sqlserver.$version.nupkg")
}
else
{

    write-host "Generating assembly versioning" -ForegroundColor Yellow
    $assemblyversion = "$version.0"

    "using System.Reflection; 

    [assembly: AssemblyVersion(`"$assemblyversion`")]
    [assembly: AssemblyFileVersion(`"$assemblyversion`")]
    [assembly: AssemblyInformationalVersion(`"$version`")]" | sc ..\src\dk.nita.saml20\CommonAssemblyInfo.cs

    write-host "Restoring nuget packages" -ForegroundColor Yellow
    .\nuget.exe restore ..\src\dk.nita.saml20

    write-host "Building solution" -ForegroundColor Yellow
    & $msbuildpath "..\src\dk.nita.saml20\dk.nita.saml20.sln" /p:Configuration=Release /p:VersionNumber=$version /p:ApplicationVersion=$version

    write-host "Building nuget package dk.nita.saml20" -ForegroundColor Yellow
    .\nuget.exe pack ..\src\dk.nita.saml20\dk.nita.saml20\dk.nita.saml20.csproj -Version $version -Symbols -Properties Configuration=Release

    write-host "Building nuget package dk.nita.saml20.ext.audit.log4net" -ForegroundColor Yellow
    .\nuget.exe pack ..\src\dk.nita.saml20\dk.nita.saml20.ext.audit.log4net\dk.nita.saml20.ext.audit.log4net.csproj -Version $version -Symbols -Properties Configuration=Release

    write-host "Building nuget package dk.nita.saml20.ext.sessionstore.sqlserver" -ForegroundColor Yellow
    .\nuget.exe pack ..\src\dk.nita.saml20\dk.nita.saml20.ext.sessionstore.sqlserver\dk.nita.saml20.ext.sessionstore.sqlserver.csproj -Version $version -Symbols -Properties Configuration=Release
}