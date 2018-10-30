Function Get-DBObjectsIntoFolders ()
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
                     Create DATE  : 10-30-2018
              Last Modified DATE  : 10-30-2018
            .REQUIRES : This script must be run on a box that has SQL Server Management tools loaded
#>

  [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Low")] 
    param(
            [Parameter(Mandatory = $true)][string] $server, # Folder where files to be zipped are located 
            [Parameter(Mandatory = $true)][string] $dbname # Folder where Zip file will go to 
          #  [Parameter(Mandatory = $true)][string] $ZipFileName, # Name to give Zip file
          #  [Parameter(Mandatory = $true)][INT]    $archivemonths, # Number of months back to start Archive
          #  [Parameter(Mandatory = $true)][string] $Extension,  # Extention to filter by
          #  [Parameter(Mandatory = $true)][BOOL]   $Delete # Should original files be deleted?

          )
# Run this first - only good for this session
#Set-ExecutionPolicy Bypass -Scope Process 
$ErrorActionPreference = 'Continue'
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
    # Load Sql.SMO dll    
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null
    $SMOserver = New-Object ('Microsoft.SqlServer.Management.Smo.Server') -argumentlist $server

        ###########=~ Set Log File Values Here ~=#####################################################
	    $LogFilePath = ".\Logs\" #store logs in a local folder called 'Logs' 
	    $LogName = "$($server)_$dbname"
	    $LogFileDir = "$LogFilePath$LogName\"
	    $LogFileName = "$($LogName)_$((Get-Date).tostring("yyyy.MM.dd.HHmm"))"
	    $LogFileExt = ".txt"
	    $LogFileFullPath = "$LogFileDir$LogFileName$LogFileExt"
	    $LogFile = Enable-LogFile -Path $LogFileFullPath # Turn ON logging
	    ########=~ Script configuration Ends here ~=#################################################
	    #############################################################################################> 
       
try{
    
    #Write-Host -F Cyan " $(get-date) - LogFilePath: $LogFilePath" 

       If($OutputType -eq 0){Write-Host -F Green "*** Script Start -  - Full Script Path: $path ***"}
           
         #  1..10 | % {Write-Host "INSERT INTO [dbo].[Test]  ([Name]) VALUES ('Joe$_')" }

            
            If($OutputType -eq 0)
            {  
             Write-Debug " - Full Script Path: $path"
             Write-Debug " - Script run from Path: $scriptPath"
             Write-Debug " - ErrorActionPreference: $ErrorActionPreference"
             Write-Debug " - DebugPreference: $DebugPreference"
             Write-Debug " - LogFileName: $LogFileName"
             Write-Debug " - LogFileFullPath: $LogFileFullPath"
             Write-Debug " - Server: $Server"
             Write-Debug " - dbname: $dbname"
           #  Write-Debug " - LogFileFullPath: $LogFileFullPath"
             

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

$server = "srp-sql"
$dbname = "srp-Inventory"

Get-DBObjectsIntoFolders -server $server -dbname $dbName