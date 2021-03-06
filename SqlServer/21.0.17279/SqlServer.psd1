
#
# Module manifest for module 'SqlServer'
#
# Generated by: Microsoft Corporation
#
# 

@{

# Script module or binary module file associated with this manifest.
RootModule = 'SqlServer.psm1'

# Version number of this module.
ModuleVersion = '21.0.17279'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '97C3B589-6545-4107-A061-3FE23A4E9195'

# Author of this module
Author = 'Microsoft Corporation'

# Company or vendor of this module
CompanyName = 'Microsoft Corporation'

# Copyright statement for this module
Copyright = 'Copyright (c) 2018 Microsoft. All rights reserved.'

# Description of the functionality provided by this module
Description = 'This module allows SQL Server developers, administrators and business intelligence professionals to automate database development and server administration, as well as both multidimensional and tabular cube processing.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
DotNetFrameworkVersion = '4.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '4.0'

# Processor architecture (None, X86, Amd64) required by this module
# Getting rid of the requirement of a 64-bit machine as this leads the module unusable on Linux/mac
# https://github.com/PowerShell/PowerShell/issues/6533
# The only cmdlet that does not work on a 32-bit OS is Invoke-Sqlcmd. Though on a 64-bit OS this cmdlet works as usual.
ProcessorArchitecture = 'None'

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @( )

# Script files (.ps1) that are run in the caller's environment prior to importing this module
# ScriptsToProcess = @()

# The type and format files are loaded explicitly in the SqlServer.psm1 file as these elements aren't supported on PS Core on linux/mac.
# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = 'sqlprovider.types.ps1xml'

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = 'sqlprovider.format.ps1xml'

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module
FunctionsToExport = @('SQLSERVER:')

# Cmdlets to export from this module
CmdletsToExport = @(
    'Add-RoleMember',
    'Add-SqlAvailabilityDatabase',
    'Add-SqlAvailabilityGroupListenerStaticIp',
    'Add-SqlAzureAuthenticationContext',
    'Add-SqlColumnEncryptionKeyValue',
    'Add-SqlFirewallRule',
    'Add-SqlLogin',
    'Backup-ASDatabase',
    'Backup-SqlDatabase',
    'Complete-SqlColumnMasterKeyRotation',
    'ConvertFrom-EncodedSqlName',
    'ConvertTo-EncodedSqlName',
    'Convert-UrnToPath',
    'Disable-SqlAlwaysOn',
    'Enable-SqlAlwaysOn',
    'Export-SqlVulnerabilityAssessmentBaselineSet',
    'Export-SqlVulnerabilityAssessmentScan',
    'Get-SqlAgent',
    'Get-SqlAgentJob',
    'Get-SqlAgentJobHistory',
    'Get-SqlAgentJobSchedule',
    'Get-SqlAgentJobStep',
    'Get-SqlAgentSchedule',
    'Get-SqlBackupHistory',
    'Get-SqlColumnEncryptionKey',
    'Get-SqlColumnMasterKey',
    'Get-SqlCredential',
    'Get-SqlDatabase',
    'Get-SqlErrorLog',
    'Get-SqlInstance',
    'Get-SqlLogin',
    'Get-SqlSmartAdmin',
    'Grant-SqlAvailabilityGroupCreateAnyDatabase',
    'Import-SqlVulnerabilityAssessmentBaselineSet',
    'Invoke-ASCmd',
    'Invoke-PolicyEvaluation',
    'Invoke-ProcessASDatabase',
    'Invoke-ProcessCube',
    'Invoke-ProcessDimension',
    'Invoke-ProcessPartition',
    'Invoke-ProcessTable',
    'Invoke-Sqlcmd',
    'Invoke-SqlColumnMasterKeyRotation',
    'Invoke-SqlVulnerabilityAssessmentScan'
    'Join-SqlAvailabilityGroup',
    'Merge-Partition',
    'New-RestoreFolder',
    'New-RestoreLocation',
    'New-SqlAvailabilityGroup',
    'New-SqlAvailabilityGroupListener',
    'New-SqlAvailabilityReplica',
    'New-SqlAzureKeyVaultColumnMasterKeySettings',
    'New-SqlBackupEncryptionOption',
    'New-SqlCertificateStoreColumnMasterKeySettings',
    'New-SqlCngColumnMasterKeySettings',
    'New-SqlColumnEncryptionKey',
    'New-SqlColumnEncryptionKeyEncryptedValue',
    'New-SqlColumnEncryptionSettings',
    'New-SqlColumnMasterKey',
    'New-SqlColumnMasterKeySettings',
    'New-SqlCredential',
    'New-SqlCspColumnMasterKeySettings',
    'New-SqlHADREndpoint',
    'New-SqlVulnerabilityAssessmentBaseline',
    'New-SqlVulnerabilityAssessmentBaselineSet',
    'Read-SqlTableData',
    'Read-SqlViewData',
    'Remove-RoleMember',
    'Remove-SqlAvailabilityDatabase',
    'Remove-SqlAvailabilityGroup',
    'Remove-SqlAvailabilityReplica',
    'Remove-SqlColumnEncryptionKey',
    'Remove-SqlColumnEncryptionKeyValue',
    'Remove-SqlColumnMasterKey',
    'Remove-SqlCredential',
    'Remove-SqlFirewallRule',
    'Remove-SqlLogin',
    'Restore-ASDatabase',
    'Restore-SqlDatabase',
    'Resume-SqlAvailabilityDatabase',
    'Revoke-SqlAvailabilityGroupCreateAnyDatabase',
    'Save-SqlMigrationReport',
    'Set-SqlAuthenticationMode',
    'Set-SqlAvailabilityGroup',
    'Set-SqlAvailabilityGroupListener',
    'Set-SqlAvailabilityReplica',
    'Set-SqlAvailabilityReplicaRoleToSecondary',
    'Set-SqlColumnEncryption',
    'Set-SqlCredential',
    'Set-SqlErrorLog',
    'Set-SqlHADREndpoint',
    'Set-SqlNetworkConfiguration',
    'Set-SqlSmartAdmin',
    'Start-SqlInstance',
    'Stop-SqlInstance',
    'Suspend-SqlAvailabilityDatabase',
    'Switch-SqlAvailabilityGroup',
    'Test-SqlAvailabilityGroup',
    'Test-SqlAvailabilityReplica',
    'Test-SqlDatabaseReplicaState',
    'Test-SqlSmartAdmin',
    'Write-SqlTableData' )

# Variables to export from this module
# VariablesToExport = @()

# Aliases to export from this module
AliasesToExport = @('Decode-SqlName', 'Encode-SqlName')

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'SQL', 'SqlServer', 'SQLPS', 'Databases', 'SqlAgent', 'Jobs', 'SSAS', 'AnalysisServices', 'Tabular', 'Cubes', 'SSIS', 'ExtendedEvents', 'xEvents', 'VulnerabilityAssessment'

        # A URL to the license for this module.
        LicenseUri = 'https://docs.microsoft.com/sql/relational-databases/scripting/sql-server-powershell-license-terms'

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        IconUri = 'https://go.microsoft.com/fwlink/?linkid=842808'

        # ReleaseNotes of this module
        ReleaseNotes = @'
## 21.0.17279
Fixes:
* Fixed issue in Invoke-ProcessASdatabase  which was throwing an exception when
  processing large tables.

Updates:
* Name parameter on Get-SqlDatabase has been aliased as Database.
* Added -ErrorLogSizeKb parameter to Set-SqlErrorLog cmdlet.

## 21.0.17262
Fixes:
* Added StatementTimeout parameter in Backup-SqlDatabase cmdlet with default
  as 0 (no timeout). This fixes the case where Backup operations running longer
  than 10 mins used to timeout. 
* Fixed issue with Always Encrypted cmdlets, where NewtonSoft.Json assembly did
  not load.
* Fixed the issue where Instance name was showing up as empty string on directly 
  creating a SMO.Server object after SqlServer module is imported.

Updates:
* Updated Get-SqlInstance cmdlet. This cmdlet now utilizes SMO and supports 
  all server instances exposed via SMO.
  This cmdlet is now supported on PowerShell 6 as well
* Important: Get-SqlInstance no longer uses CloudAdapter for Sql IaaS instances
  as CloudAdapter stopped shipping from SQL 2016 onwards.
  Users that still use this cmdlet for Sql 2014 IaaS instances 
  should revert to an older version of the SqlServer module.
* Added the following Vulnerability Assessment cmdlets:
    Export-SqlVulnerabilityAssessmentBaselineSet
    Export-SqlVulnerabilityAssessmentScan
    Import-SqlVulnerabilityAssessmentBaselineSet
    Invoke-SqlVulnerabilityAssessmentScan
    New-SqlVulnerabilityAssessmentBaseline
    New-SqlVulnerabilityAssessmentBaselineSet

## 21.0.17240
Fixes:
* Fixed issue where PowerShell was not able to find cmdlets in the module
  unless the user did an explicit ''Import-Module SQLServer''

Updates:
* Added Get-SqlBackupHistory cmdlet
* Ported PS Provider to .NET Core for PowerShell 6 support
* Ported a subset of cmdlets to .NET Core for PowerShell 6 support
* Powershell 6 support on macOS and Linux in Preview.
* To use SqlServer provider on macOS and Linux mount it using a new PSDrive.
  Examples in documentation. 
* Removed restriction of 64-bit OS for this module. Note: Invoke-Sqlcmd 
  cmdlet is the only cmdlet not supported on 32-bit OS. 

## 21.0.17224
Fixes:
* Added logic to prevent the module from being installed on PowerShell Core
* Fixed SqlServer Provider for SSIS

Updates:
* Added support for PSCredential to Invoke-Sqlcmd

## 21.0.17199
Fixes:
* Fixed issue in New-SqlAvailabilityGroup cmdlet when targeting SQL Server 2014

Updates:
* Updated SQL Server provider (SQLRegistration) to display AS/IS/RS groups
* Added -LoadBalancedReadOnlyRoutingList parameter to Set-SqlAvailabilityReplica
  and New-SqlAvailabilityReplica

## 21.0.17178
Updates:
* Updated AnalysisService Cmdlet to use cached login token from Login-AzureAsAccount for Azure Analysis Services.
* Update Backup-ASDatabase and Restore-ASDatabase to support Azure Analysis Services.

## 21.0.17152
Bug Fixes:
* Fixed issue where Invoke-SqlCmd was throwing an error due to
  missing MSVCR120.dll (now included with the module).
* Fixed issue where 'Deploy to Azure Automation' was not working.
* Fixed issue where the SQL Provider was unable to enumerate some containers
  (e.g. Databases) when the module was loaded by passing Import-Module any
  of the -Version/-MinimumVersion/-MaximumVersion parameters.
* Fixed issue in Set-SqlColumnEncryption where the -LogFileDirectory option 
  was not dumping DacFx logs.
* Updated Tags and Description in the manifest file.
* Updated link to License.

Updates:
* Added new parameter '-CertificateThumbprint' to Add-SqlAzureAuthenticationContext
  cmdlet.

## 21.0.17099
First version of SQL PowerShell Module on PSGallery.

'@

        # External dependent modules of this module
        # ExternalModuleDependencies = ''

    } # End of PSData hashtable
    
 } # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''
}

# SIG # Begin signature block
# MIIppQYJKoZIhvcNAQcCoIIpljCCKZICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCf7QskLKot0UT1
# 1SHfdBp0qbJUfPevcTjXW4/pMQXqX6CCDYMwggYBMIID6aADAgECAhMzAAAAxOmJ
# +HqBUOn/AAAAAADEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTcwODExMjAyMDI0WhcNMTgwODExMjAyMDI0WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCIirgkwwePmoB5FfwmYPxyiCz69KOXiJZGt6PLX4kvOjMuHpF4+nypH4IBtXrL
# GrwDykbrxZn3+wQd8oUK/yJuofJnPcUnGOUoH/UElEFj7OO6FYztE5o13jhwVG87
# 7K1FCTBJwb6PMJkMy3bJ93OVFnfRi7uUxwiFIO0eqDXxccLgdABLitLckevWeP6N
# +q1giD29uR+uYpe/xYSxkK7WryvTVPs12s1xkuYe/+xxa8t/CHZ04BBRSNTxAMhI
# TKMHNeVZDf18nMjmWuOF9daaDx+OpuSEF8HWyp8dAcf9SKcTkjOXIUgy+MIkogCy
# vlPKg24pW4HvOG6A87vsEwvrAgMBAAGjggGAMIIBfDAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUy9ZihM9gOer/Z8Jc0si7q7fDE5gw
# UgYDVR0RBEswSaRHMEUxDTALBgNVBAsTBE1PUFIxNDAyBgNVBAUTKzIzMDAxMitj
# ODA0YjVlYS00OWI0LTQyMzgtODM2Mi1kODUxZmEyMjU0ZmMwHwYDVR0jBBgwFoAU
# SG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29kU2lnUENBMjAxMV8yMDEx
# LTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYBBQUHMAKGRWh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljQ29kU2lnUENBMjAxMV8y
# MDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQAG
# Fh/bV8JQyCNPolF41+34/c291cDx+RtW7VPIaUcF1cTL7OL8mVuVXxE4KMAFRRPg
# mnmIvGar27vrAlUjtz0jeEFtrvjxAFqUmYoczAmV0JocRDCppRbHukdb9Ss0i5+P
# WDfDThyvIsoQzdiCEKk18K4iyI8kpoGL3ycc5GYdiT4u/1cDTcFug6Ay67SzL1BW
# XQaxFYzIHWO3cwzj1nomDyqWRacygz6WPldJdyOJ/rEQx4rlCBVRxStaMVs5apao
# pIhrlihv8cSu6r1FF8xiToG1VBpHjpilbcBuJ8b4Jx/I7SCpC7HxzgualOJqnWmD
# oTbXbSD+hdX/w7iXNgn+PRTBmBSpwIbM74LBq1UkQxi1SIV4htD50p0/GdkUieeN
# n2gkiGg7qceATibnCCFMY/2ckxVNM7VWYE/XSrk4jv8u3bFfpENryXjPsbtrj4Ns
# h3Kq6qX7n90a1jn8ZMltPgjlfIOxrbyjunvPllakeljLEkdi0iHv/DzEMQv3Lz5k
# pTdvYFA/t0SQT6ALi75+WPbHZ4dh256YxMiMy29H4cAulO2x9rAwbexqSajplnbI
# vQjE/jv1rnM3BrJWzxnUu/WUyocc8oBqAU+2G4Fzs9NbIj86WBjfiO5nxEmnL9wl
# iz1e0Ow0RJEdvJEMdoI+78TYLaEEAo5I+e/dAs8DojCCB3owggVioAMCAQICCmEO
# kNIAAAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDExMB4XDTExMDcwODIwNTkwOVoXDTI2MDcwODIxMDkw
# OVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UE
# AxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6qghBNNLrytlghn0IbKmvpWlCq
# uAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJDXlkh36UYCRsr55JnOlo
# XtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv56sIUM+zRLdd2MQuA3Wr
# aPPLbfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN1Vx5pUkp5w2+oBN3vpQ9
# 7/vjK1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+sYxd6IlPhBryoS9Z5JA7
# La4zWMW3Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzluZH9TupwPrRkjhMv0ugOG
# jfdf8NBSv4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKuHCOnqWbsYR9q4ShJnV+I
# 4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8rAKCX9vAFbO9G9RVS+c5
# oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/CHFfbg43sTUkwp6uO3+xbn6/83bBm
# 4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/dygo8e1twyiPLI9AN0/B
# 4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE2rCIF96eTvSWsLxGoGyY0uDW
# iIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUSG5k
# 5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYD
# VR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUci06AjGQQ7kU
# BU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybC5taWNyb3Nv
# ZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAz
# XzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUHMAKGQmh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAz
# XzIyLmNydDCBnwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3LgMwgYMwPwYIKwYBBQUH
# AgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvZG9jcy9wcmltYXJ5
# Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBwAG8AbABpAGMA
# eQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAZ/KG
# pZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVfLiw++MNy0W2D/r4/6ArKO79H
# qaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS0LD9a+M+By4pm+Y9G6XU
# tR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELukqQUMm+1o+mgulaAqPypr
# WEljHwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q3fMOr5kol5hNDj0L8giJ
# 1h/DMhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgycScaf7H0J/jeLDogaZiy
# WYlobm+nt3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8VfUWnduVAKmWjw11SYobD
# HWM2l4bf2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbRBrF1HxS+YWG18NzGGwS+
# 30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/QACnFsZulP0V3HjXG0qKi
# n3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL/9azI2h15q/6/IvrC4Dq
# aTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4ETIheu9BCrE/+6jMpF3BoYibV3FW
# TkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xght4MIIbdAIBATCBlTB+MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNy
# b3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAAxOmJ+HqBUOn/AAAAAADE
# MA0GCWCGSAFlAwQCAQUAoIHaMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCqabhF
# MuKk7pFMurPnmKTKS0hVs7tXky1frZwBeg7Z7DBuBgorBgEEAYI3AgEMMWAwXqA6
# gDgAUwBRAEwAIABTAGUAcgB2AGUAcgAgAE0AYQBuAGEAZwBlAG0AZQBuAHQAIABT
# AHQAdQBkAGkAb6EggB5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vc3FsLyAwDQYJ
# KoZIhvcNAQEBBQAEggEAfvPV7TeZ8BnvDvbKt6e3l+KCI5EOjmCz4r0+V68NK4Nb
# NI80UdEBIsbR6i74uGw88NXBub+pe8RE+1VVX+cpNa+O7WwSdnfPqyPPoxr5kcD6
# byqYK70yTp9+VUoQP+QsgoJlFkzdVIHtbPObw7cpcQakrMBsAdbuT/RTgXJuHeBR
# VmL8H3Iso0hc1J+J+YzQFhSa9ANbMf9biLY1TRBo+VBw2IltOrJBArrRaqTozL0C
# Hj/30x/Ajvhk8Bx3Ii20nLCgnWWMxVjwLO1lGyJwZ3ydNAilEAu5VP8U5UmCyRe0
# ae9tZAF5K0iFwxfCzZTnup5Ce/zSUoyq6Fgcem9jmKGCGNYwghjSBgorBgEEAYI3
# AwMBMYIYwjCCGL4GCSqGSIb3DQEHAqCCGK8wghirAgEDMQ8wDQYJYIZIAWUDBAIB
# BQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAx
# MA0GCWCGSAFlAwQCAQUABCBiBmwJqIbCHThWSNk0IqOgIHrgB2GqHfprBlZuHLTa
# aQIGWyqrcC5KGBMyMDE4MDYyNzE3NDUyNy42MDVaMASAAgH0oIHQpIHNMIHKMQsw
# CQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpEMDgyLTRCRkQtRUVCQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# c2VydmljZaCCFC0wggTxMIID2aADAgECAhMzAAAAxjhmw94i+PCkAAAAAADGMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE4
# MDEzMTE5MDA0OFoXDTE4MDkwNzE5MDA0OFowgcoxCzAJBgNVBAYTAlVTMQswCQYD
# VQQIEwJXQTEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODItNEJGRC1FRUJB
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBzZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkH4h3fxEnNJi5YZyHInQJhAGlWq7uDZa
# 4a96jiP38BSZzvLIq8+ylNNUO3WMM0KbtbYCv5EbQQB3cZZU0rsykke/eOlpXQ+q
# j8ljeHwEzxyYCvnyun+bcNjbXd/uTvim3o9jaPPCNi5RzWVJWGTulZgMafWWud8R
# EIFE3PgUGNjcMi6CSaGRtmJOy9Hi3sUsLi8kk6ssypbkd7cpHm51PkgKBsvzwkmd
# a6nGQXULh0iPBOawZW3MfBSFJHIl6zE8CxqYz/ipyvafjl0/Z9mW2bzyg/A/i3q9
# HCpfL4mDwOP2ZM8jgwzDzq3nWkgQIDH3R6a7YN++HCf2+RP0JZwJfQIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFElH4jhAiE1kqkC8UUpGBPcU1IkzMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBADgjMOVYEXToV2oo9tAMUqNlkfiGbm/AMJ7b8FHuYFmN
# VK8xjZ/nF0U2zRA0hvcFiBScN4MnU8hR9YwDY/l6mLfK0nMDc16ZEaMjxeQoKj5d
# kOfzOqIqvH0bpuXrn2QQVT3+KGb360z/AVMdlOGnJrNFFLpfjiDB372Ju4aX1MIE
# yMbQjmbPN58v2eMiS58W6XVN3JtBFNMz/9GJPqGg7a5VaKmxF1SGsaCg6SrhCInj
# N4xm0vE2QQrngLkgWQKAFT3zyOOXwwNI6VKdgzkpJh/4hkKiwaq/krzuW3QmmUj7
# OSkE0KgToKqQhMDXAjXxqJv3swz4uTMVv1ziVjx1JZMwggXtMIID1aADAgECAhAo
# zDolv7pErESam1hrQzmqMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA2MjMyMTU3MjRaFw0zNTA2
# MjMyMjA0MDFaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
# MjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALkInijk5OwGTlBo
# s0HFe+uuto6vgboiRB9lNGlMvnBAF/IWe+J5/YbtDTn0G6itkpAeyz12j1rZtZEQ
# LjwFjYptJFTnH+1WrYO0UJwVpRd0iFkg/AjFhHbTaNRvKHjOXLjzUJBE/+NjX76h
# miyWFQTWB/4ehCHgQjERxCg2lM9QpGKeydarcQCyWwzmltQKJJb1/8bVtxvXy7ch
# Yq8S3KFdN+Ma+xpGmMCbwOdjHyoIkwJ+HmqO8p8YieQihaKxhFdA//UO2G+c7eJF
# MQHNF+l/sIFF46ohQCahcqqnTzwBBX7ug1ixXgZjmWKReIK3DZMMJGq0G9sn7F+V
# BD+TSjD1lxizp/kZp5MzHQHI2yJSXNclyUb5ovuHWUO+m2KxjS2GRBpGrHhhfjAJ
# +q6JxEEqImYDkTlFnMeLDKjKDS/7UuoM92MzI53+sB+tZ9anUAPGBHBjtSyxhlpD
# t/uu+W4pbiEhQSYGjMnD7rDChZOhuYXZ5jJsS0w/1l2j5bWdd8OcwFW3dADjuDir
# g5dQ4ZpCJB3GwKMw0RpayFI093PxxxgfM6167MtBYPMjlCDCSEWsXFHGLoDC4ncV
# vYWH7TadlpHuALWjcOyf442AaIN2uq9dcFIiFuJm+7qzxcL3Pi93psrewabGSEzD
# N1Ej0yfXuE5wlvChRHaveM+a4WYTAgMBAAGjUTBPMAsGA1UdDwQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTV9lbLj+iiXGJo0T2UkFvXzpoYxDAQBgkr
# BgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQsFAAOCAgEArKWWjL+7rqb213GHQzFW
# iP0cMnFbNbfU8JHyrzfiFPHzAiYFPhYUfxS6uE/7ibKy59QJzG25WztkZXBmt/Kx
# Wt8aAvP1UbhnbXnzv1Z75IS5Kx6bQJwmNPlHGJhp2BzXttG/j2HCZ8S172BDjhAb
# NknkIMqtp8GxJ2UJ+M31WyrQhDPz7x/y9ZwLWJM3oHWg3nLebHUqZiL1jAYwVp9A
# uTCqQHcVgteL7MDTsr2DxXcMHq6vGVOgTXlxnw+vMM5n+dYszCJBegfyl0IYzll5
# EFXebxDkuNqDZkAWCWgjW5cuJpoCu1eMxbi6aWIygImeof3Aknx7KzMZhCpjxQBo
# YvqfR42ZekU6p+nt7mlCtfOBm0dWEHv8cDaEGHPq7/mXTZ4zI90mC7oqtz9E3IMn
# /71hWSsRt8pP28WLDBwxrjL4+LlC93/cYZp2sVoE4RE9ZkW3GHG+ySSF1vPUukE0
# XRItJbmNphNIbUuwB32ZkwlhgXRXJoqraePk2ceIzCTY7FIkXB68kRTilt7rCtqe
# 3V+zW9vUguzGIFCHJUA6+8fuzf4z5W7DhAlVAyU5wOk1XWUxqPa/oAnNKcezNjIu
# 3JXzg8Faz4uN9uqzIfik7R4xDrZMEatgC6QSIyIXozZkgpEEEuCrbx7LUAVhtED/
# WYZx0dUzaXypc4o412QM8WkwggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0GCSqG
# SIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
# MjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYr
# W/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaC
# o0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijGGvmG
# gLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/9WbA
# A5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9pAHB
# IAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUBBAMC
# AQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcUAgQM
# HgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1Ud
# IwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0
# dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKG
# Pmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0
# XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcuAzCB
# gTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9kb2Nz
# L0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQ
# AG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsF
# AAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LFZslq
# 3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPleFzWY
# JFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6AG9L
# MEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQjP9q
# Yn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9MalCpaG
# pL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacRy5rY
# DkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo+KhI
# q/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZeodz
# OwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMRZjDT
# u3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/XU/p
# nR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKhggLOMIICNwIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNV
# BAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIHNlcnZpY2WiIwoBATAHBgUrDgMCGgMVACRcAAFsN8hE
# NKmIjVzXRAdThQc5oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDe3bulMCIYDzIwMTgwNjI3MTUzMDQ1WhgPMjAx
# ODA2MjgxNTMwNDVaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAN7du6UCAQAwCgIB
# AAICD2kCAf8wBwIBAAICEgQwCgIFAN7fDSUCAQAwNgYKKwYBBAGEWQoEAjEoMCYw
# DAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0B
# AQUFAAOBgQAusaq67N2owtoIoLeyxOVR5+mMRz3vcSeKrnU5tM2nYX4NRujZhrnU
# Ml64lt2wd9OlIngNFMyo6A936JRio2kUznI22uBnPxPbuVt8afdRN/81A8Onbkv3
# UW2o2SAJ05eKioOZcMw7vCSJzTH6GYCZCFLGcXQrXRIzvtZTsnrOJzGCAw0wggMJ
# AgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAAxjhmw94i
# +PCkAAAAAADGMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZI
# hvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIIm7PaZqy5IMHpRefMTFZy5D7jZuSuPD
# MoCRm+kW+OvzMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg2PMMN8qpjQLZ
# CL65aYVwC08SQGWX+O/fvaz9c/M1tOwwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAMY4ZsPeIvjwpAAAAAAAxjAiBCCZVMXksJO5+5Yj
# vqHkFc8oQ8VaM3zBRLPAxAd+RJ1gYDANBgkqhkiG9w0BAQsFAASCAQBYb+GFyICc
# xecRcgR9jix4p/LSKBVvYbqq83DUTN5EhWOrjPD12mUW1EXY+CrSr0Fe5mKZbFXk
# ITOdY5P6959W/j1Tn7j1Wfsd8phGoyZwbTe2TulpaOn54vgttU9DqKLENL1aJC1n
# rLGBrAYPPXQbw99F0mVS1eD19b2vrqV16YLyJcYxYHtlx2ZfF04PNKdKdFpa/p58
# Fi+cWvrmPcvOc9R7qrNiYKAT5X8diGnn72cBiwNiHEavOV28A4JCaRUmtPmesF3U
# lIiHR1ZFi21Lx9cRkG1fvdB/OzOY/zYPdNrfuFuYBAaepKY5jl3jFxyoHzeRdXq/
# pNpwvwwLP65e
# SIG # End signature block
