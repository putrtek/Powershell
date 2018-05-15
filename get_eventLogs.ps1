Function Get-EventLog ()
{
 <#
                    .SYNOPSIS
                        script to get Windows Event Logs for the last XX days. 
                        Export logs to a CSV files. Zip files and copy to xxx Location. 
                    .DESCRIPTION
                        Script to get Windows Application and System Event Logs for the last XX days. 
                        Export log to a CSV files. Zip files and copy to xxx Location.
                        Then move ZIP to $ZiPDestination folder 
                    .PARAMETER Servers 
                        List of server names
                    .PARAMETER ZiPDestination
                        Full Path to the folder where ZIP file should go.
                    .PARAMETER ZipName
                        The Name for the zip file - Default name will be the name of the file with a ZIP extention
                    .PARAMETER Extension
                        Extention for the type of file to be ZIPPED ie: ".trc"
                    .PARAMETER Hours
                        #Num of Hours before the current Time. Only files OLDER then this date will be archived. use 0 for ALL files; 30 days = 720 hours
                    .EXAMPLE
                        Compress-Folders -SourcePath $SourcePath -ZiPDestination $ZiPDestination -ZipName $ZipName -Extension $Extension -Hours $Hours
                    .NOTES
                                  AUTHOR  : Mark Buckley NNSY C109.33 IT Solutions mark.c.buckley@navy.mil 757.396.8821 
                             Create DATE  : 01.01.2017
                      Last Modified DATE  : 05.01.2018
                      # Set-ExecutionPolicy bypass -Scope Process
        #>

        [CmdletBinding( DefaultParameterSetName="SourcePath", ConfirmImpact='Low')]
        PARAM(
                [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
                [ValidateNotNullOrEmpty()]
                [STRING[]]$Servers,

                [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({Test-Path -PathType container -Path $_})]
                [STRING[]]$ZiPDestination,
 
                [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=2)]
                [ValidateNotNullOrEmpty()]
                [STRING[]]$ZipName,

                [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=3)]
                [ValidateNotNullOrEmpty()]
                [STRING[]]$LogNames
<# 
                [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=4)]
                [ValidateNotNullOrEmpty()]
                [int]$Hours #Number of Hours before the current Time Only files OLDER then this date will be archived
                #>
            )
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
                     $CutDay = [DateTime]::Now.AddHours(-$Hours) # Only files OLDER then this date will be archived
                    If($OutputType -eq 0)
                    {
                        Write-Host -F Green "*** Script Start -  - Full Script Path: $path ***"
                        Write-Host -f Green "Servers: $Servers "
                        Write-Host -f Green "ZiPDestination: $ZiPDestination "
                        Write-Host -f Green "ZipFileFullPath: $ZipFileFullPath "
                        Write-Host -f Green "LogFileFullPath: $LogFileFullPath "
                        Write-Host -f Green "Extension: $Extension "
                        Write-Host -f Green "Hours: $Hours "
                        Write-Host -f Green "CutDay: $CutDay " 
                    }
        
                    # 10..20 | % {New-Item -Name SQLServerTrace$_.trc -ItemType File}
                } # End Begin
            process 
            {
                try
                {
                    # Create Remote connection 
                    Foreach($server in $Servers)
                    {
                      Foreach($log in $Lognames)
                      {
                      #  Write-Host $server
                      #  Write-Host "$ZiPDestination\$($Server)_WindowSsyslogs.csv"
                        $session = New-PSSession -ComputerName $server
                        Invoke-Command -Session $session -ScriptBlock {Get-EventLog -LogName $log -After (Get-Date).Adddays(-30) } | export-csv $ZiPDestination\$($Server)_$(log)_Logs.csv -NoTypeInformation -Delimiter "|"
                      #  Invoke-Command -Session $session -ScriptBlock {Get-EventLog -LogName "system" -After (Get-Date).Adddays(-30) } | export-csv $ZiPDestination\$($Server)_WindowSsysLogs.csv -NoTypeInformation -Delimiter "|"
                        Remove-PSSession $session
                        #>
                      } # End LogName
                    }    #  End Servers
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

# Home Servers #########################################################################################
  #$Servers = "srp-server, putrtek-sql, "
 $Servers = "srp-server"
 $ZiPDestination = "C:\Users\PUTRTEK\Downloads\Git\Powershell"
 #$ZiPDestination = "\\snnsvr012\Code 1230\Code 1237\WebMasters\WebSite Information\Web Application Information\NVR\Code\Backup\" 
  $ZipName = "NVR_StaticWeb_Backup"
  $Lo = "*.*"
  $Hours = 0 # Adjust this number to get to the prior full month (720 hours in a month)
  $LogNames = "application, system"
  Get-EventLog -Servers $Servers # -ZiPDestination $ZiPDestination -ZipName $ZipName -Extension $Extension -Hours $Hours
###############################################################################################################################>