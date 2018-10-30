Set-ExecutionPolicy Bypass -Scope Process

Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45 -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HealthAndDiagnostics -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-LoggingLibraries -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestMonitor -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-Security -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestFiltering -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-Performance -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerManagementTools -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-IIS6ManagementCompatibility -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-Metabase -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-StaticContent -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45 -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45 -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFilter -All -Verbose
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic -All -Verbose


Import-Module WebAdministration 

New-WebAppPool -name "NewWebSiteAppPool"  -force

$appPool = Get-Item -name "NewWebSiteAppPool" 
$appPool.processModel.identityType = "NetworkService"
$appPool.enable32BitAppOnWin64 = 1
$appPool | Set-Item

mkdir "c:\Web Sites\NewWebSite"

# All on one line
new-WebSite -name "NewWebSite" `
                            -PhysicalPath "c:\Web Sites\NewWebSite" `
                            -HostHeader "home2.west-wind.com" `
                            -ApplicationPool "NewWebSiteAppPool" `
                            -force


Set-Service WinRM -ComputerName $servers -startuptype Automatic
winrm set winrm/config/client ‘@{TrustedHosts="DESKTOP-BVRO3S4"}’   



Set-PSSessionConfiguration Microsoft.PowerShell -ShowSecurityDescriptorUI
