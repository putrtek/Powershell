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


[CmdletBinding(ConfirmImpact="Low")] 
    param(
            [Parameter(Mandatory = $true)][string] $SourcePath, # Folder where files to be zipped are located 
            [Parameter(Mandatory = $true)][string] $OutputFolder, # Folder where Zip file will go to 
            [Parameter(Mandatory = $true)][string] $ZipFileName # Name to give Zip file
          # [Parameter(Mandatory = $true)][INT]    $archivemonths, # Number of months back to start Archive
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
                    $LogName = $ZipName
                    $LogFileDir = "$LogFilePath$LogName\"
                    $LogFileName = "$($LogName)_$((Get-Date).tostring("yyyy.MM.dd.HHmm"))"
                    $LogFileExt = ".txt"
                    $LogFileFullPath = "$LogFileDir$LogFileName$LogFileExt"
                    $LogFile = Enable-LogFile -Path $LogFileFullPath # Turn ON logging
                    ########=~ Script configuration Ends here ~=#################################################
                    #############################################################################################> 
                    # $CutDay = [DateTime]::Now.AddHours(-$Hours) # Only files OLDER then this date will be archived
                    If($OutputType -eq 0)
                    {
                        Write-Host -F Green "*** Script Start -  - Full Script Path: $path ***"
                        Write-Host -f Green "SourcePath: $SourcePath "
                        Write-Host -f Green "OutputFolder: $ZiPDestination "
                        Write-Host -f Green "ZipFileFullPath: $ZipFileFullPath "
                        Write-Host -f Green "LogFileFullPath: $LogFileFullPath "
                        Write-Host -f Green "ZipFileName: $ZipFileName "
                      #  Write-Host -f Green "Hours: $Hours "
                      #  Write-Host -f Green "CutDay: $CutDay " 
                    }
        
                    # 10..20 | % {New-Item -Name SQLServerTrace$_.trc -ItemType File}
                } # End Begin
            process 
            {
                try
                {
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
                $LogFile | Disable-LogFile # Turn OFF logging #>      


            } # End Process
} # End Function


$SourcePath = "srp-sql"
$OutputFolder = "srp-Inventory"
$ZipFileName = "BlahBlah"
Get-BoilerPlate -SourcePath $SourcePath -OutputFolder $OutputFolder -ZipFileName $ZipFileName