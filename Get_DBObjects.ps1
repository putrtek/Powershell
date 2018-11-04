Function Get-DBObjectsIntoFolder ()
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


[CmdletBinding(ConfirmImpact="Low")] 
    param(
        [Parameter(Mandatory = $true)][string] $server, # Folder where files to be zipped are located 
        [Parameter(Mandatory = $true)][string] $dbname,
        [Parameter(Mandatory = $true)][INT]    $DestinationPath # Number of months back to start Archive
          #  [Parameter(Mandatory = $true)][string] $Extension,  # Extention to filter by
          #  [Parameter(Mandatory = $true)][BOOL]   $Delete # Should original files be deleted?

    ) # end PARAM
    begin 
            {
                    #############################################################################################
                    ########=~ Script configuration Starts Here ~=###############################################
                    $ErrorActionPreference = "Continue"
                    $DebugPreference = 'Continue'
                    $Path = $(if ($PSVersionTable.PSVersion.Major -ge 3) { $PSCommandPath } else { & { $MyInvocation.ScriptName } })
                    $scriptPath = Split-Path -Path $Path
                    Set-Location $scriptPath
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $OutputType = 0 # 0 will output to Screen; 1 will output to Log File (sendlog function)
                    #############################################################################################>
                    # Load Powershell Logging Module if it is not loaded already...
                     If(!(Get-Module PowerShellLogging )) { Import-Module powershellLogging}
                    ###########=~ Set Log File Values Here ~=#####################################################
                    $LogFilePath = ".\Logs\" #store logs in a local folder called 'Logs' 
                    $LogName = "$($server)_$dbname"
                    $LogFileDir = "$LogFilePath$LogName\"
                    $LogFileName = "$($LogName)_$((Get-Date).tostring("yyyy.MM.dd"))"
                    $LogFileExt = ".txt"
                    $LogFileFullPath = "$LogFileDir$LogFileName$LogFileExt"
                   # $LogFile = Enable-LogFile -Path $LogFileFullPath # Turn ON logging
                    ########=~ Script configuration Ends here ~=#################################################
                    #############################################################################################> 
                     # Load Sql.SMO dll    
                    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null
                    $SMOserver = New-Object ('Microsoft.SqlServer.Management.Smo.Server') -argumentlist $server
                    $db = $SMOserver.databases[$dbname]
                        $Objects = $db.Tables
                        $Objects += $db.Views
                        $Objects += $db.StoredProcedures
                        $Objects += $db.UserDefinedFunctions

                    # Create Folders
                    $SavePath = "$DestinationPath\$($server)\$LogFileName"
                    
                   # new-item -type directory -path "$SavePath"    
              
                } # End Begin
            process 
            {
                try
                {
                    If($OutputType -eq 0)
                    {
                        Write-Host -F Green "*** Script Start -  - Full Script Path: $path ***"
                        Write-Debug " - Full Script Path: $path"
                        Write-Debug " - Script run from Path: $scriptPath"
                        Write-Debug " - ErrorActionPreference: $ErrorActionPreference"
                        Write-Debug " - DebugPreference: $DebugPreference"
                        Write-Debug " - LogFileName: $LogFileName"
                        Write-Debug " - DestinationPath: $DestinationPath"
                        Write-Debug " - LogFileFullPath: $LogFileFullPath"
                        Write-Debug " - SavePath: $SavePath"
                        Write-Debug " - Server: $Server"
                        Write-Debug " - dbname: $dbname"
                      #  Write-Host -f Green "Hours: $Hours "
                      #  Write-Host -f Green "CutDay: $CutDay " 
                    }
                  ########################################################################
                    ##  CODE GOES HERE ##
                  ########################################################################   
                } # End try
                Catch
                {
                    $scriptName = $_.InvocationInfo.ScriptName
                    $e = $_.Exception
                    $line = $_.InvocationInfo.ScriptLineNumber
                    $msg = $e.Message 
                    Write-Host -ForegroundColor Red "The Script : $scriptName"
                    Write-Host -ForegroundColor Red "caught exception: $e at $line"
                    Write-Host -ForegroundColor Red "at line number: $line"
                    Write-Host -ForegroundColor Red "error message is : $msg"
                    Break
                } # End Catch
                finally
                { Write-Host -F Green "***** Script Complete - Time to complete: $($stopwatch.Elapsed) *****"}
             #   $LogFile | Disable-LogFile # Turn OFF logging #>      


            } # End Process
} # End Function


$SourcePath = "srp-sql"
$OutputFolder = "srp-Inventory"
$ZipFileName = "BlahBlah"
$DestinationPath = "C:\Users\putrt\Downloads\powershell\SQL"
Get-DBObjectsIntoFolder -SourcePath $SourcePath -OutputFolder $OutputFolder -ZipFileName $ZipFileName -DestinationPath $DestinationPath