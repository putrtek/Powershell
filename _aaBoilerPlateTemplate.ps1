Function Get-BoilerPlate ()
{
<#
            .SYNOPSIS
                Put your synopsis here
             .DESCRIPTION
                Put your Description here...
            .EXAMPLE
                Eamples goes here...
            .NOTES
                          AUTHOR  : Mark Buckley (mark.c.buckley@navy.mil) 757.396.8821
                     Create DATE  : 05-22-2014
              Last Modified DATE  : 07-02-2014
            .REQUIRES : This script must be run on a box that has SQL Server Management tools loaded
#>

  [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Low")] 
    param(
            [Parameter(Mandatory = $true)][string] $SourcePath, # Folder where files to be zipped are located 
            [Parameter(Mandatory = $true)][string] $OutputFolder, # Folder where Zip file will go to 
            [Parameter(Mandatory = $true)][string] $ZipFileName, # Name to give Zip file
            [Parameter(Mandatory = $true)][INT]    $archivemonths, # Number of months back to start Archive
            [Parameter(Mandatory = $true)][string] $Extension,  # Extention to filter by
            [Parameter(Mandatory = $true)][BOOL]   $Delete # Should original files be deleted?

          )
# Run this first - only good for this session
#Set-ExecutionPolicy Bypass -Scope Process 
$ErrorActionPreference = "Stop"
$DebugPreference = 'Continue'
$Path = $(if ($PSVersionTable.PSVersion.Major -ge 3) { $PSCommandPath } else { & { $MyInvocation.ScriptName } })
$scriptPath = Split-Path -Path $Path
Set-Location $scriptPath
#Write-Debug "DEBUG is turned ON!"
#Write-Debug "Full Script path is: $Path "
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

	# Load Powershell Modules if it is not loaded already...
    If(!(Get-Module PowerShellLogging )) { Import-Module ./PS_Functions/powershellLogging/powershellLogging.psm1 -Verbose}
    If(!(Get-Module Fumnctions )) { Import-Module ./PS_Functions/Functions/Functions.psm1 -Verbose}
        
        ###########=~ Set Log File Values Here ~=#####################################################
        $LogFilePath = ".\Logs\" #Prod
        #$LogFilePath = "\\testsvr011\apps\BMS32\Logs" #TEST
        $LogName = "BoilerPlate"
        $LogFileDir = $LogFilePath
        $LogFileName = "$($LogName)_$((Get-Date).tostring("yyyy.MM.dd.Hmm"))"
        $LogFileExt = ".txt"
        $LogFileFullPath = "$LogFileDir$LogFileName$LogFileExt"
        $LogFile = Enable-LogFile -Path $LogFileFullPath # Turn ON logging
        ##############################################################################################
        ###########=~ Set Values Here ~=#######################################################
         #$sqlinstance = "TESTSVR017\ISRB"  # Name of SQL Server -- on TEST
         $sqlinstance = "SNNSVR002"         # Name of SQL Server -- on PROD
         $Database = "NMCI_Info"            # Name of DataBase
         $CSVFileName = 'AD_Dump_NMCI' 
         $CSVPathFileName = "$scriptPath\$CSVFileName.txt"
         $OutputType = 0 # 0 will output to Screen; 1 will output to Log File (sendlog function)
         $LogFileName = 'ADDump-NMCI-Results'
         ########################################################################################

try{
    
    #Write-Host -F Cyan " $(get-date) - LogFilePath: $LogFilePath" 

       If($OutputType -eq 0){Write-Host -F Green "*** Script Start -  - Full Script Path: $path ***"}
           
         #  1..10 | % {Write-Host "INSERT INTO [dbo].[Test]  ([Name]) VALUES ('Joe$_')" }

            
            If($OutputType -eq 0)
            {  
             Write-Debug " - Full Script Path: $path"
             Write-Debug " - Script run from Path: $scriptPath"
             Write-Debug " - CSVFileName: $CSVFileName"
             Write-Debug " - CSVPathFileName: $CSVPathFileName"
             Write-Debug " - sqlinstance: $sqlinstance"
             Write-Debug " - LogFileFullPath: $LogFileFullPath"
             Write-Debug " - ErrorActionPreference: $ErrorActionPreference"
             Write-Debug " - DebugPreference: $DebugPreference"

             #  Write-Debug " - LogFileFullPath: $LogFileFullPath"
             #  Write-Debug " - LogFileFullPath: $LogFileFullPath"
                         
            }
           
            
            # Create some files for us to use.
            #1..30 | % {New-Item -Name Joe$_.xml -ItemType File}
            # 1..30 | % {Write-Host "INSERT INTO [dbo].[Test]  ([Name]) VALUES ('Joe$_')" }

            #>
        
        # ################## Add Script block here ######################
       # $scriptblock = {ldifde -f ./ad.txt -r "(sAMAccountName=mark.c.buckley)" }
      #  Invoke-Command -scriptblock $scriptblock 
        
        #ldifde -f C:\Users\mark.c.buckley\Downloads\Powershell\ActiveDirectory\LDIFDE\NMCI_Buckley.txt -r "(sAMAccountName=mark.c.buckley)"
     }
   Catch
   {
        $Command = $($_.InvocationInfo.MyCommand) 
        $scriptName = $_.InvocationInfo.ScriptName
        $e = $_.Exception
        $line = $_.InvocationInfo.ScriptLineNumber
        $msg = $e.Message 
        
        Write-Host -F Red "The Script : $scriptName"
        Write-Host -F Red "caught exception: $e at $line"
        Write-Host -F Red "at line number: $line"
        Write-Host -F Red "The Command : $Command"
        Write-Host -F Red "error message is : $msg"
       Break

    }
    finally
    { Write-Host -F Green "***** Script Complete - Time to complete: $($stopwatch.Elapsed) *****"}
    $LogFile | Disable-LogFile # Turn OFF logging

} # End Function

Get-BoilerPlate