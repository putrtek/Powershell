Function Get-DBObjectsIntoFolder ()
{
<#
            .SYNOPSIS
                Create TSQL script for all object in a database 
             .DESCRIPTION
                Create TSQL script for all object in a database 
            .EXAMPLE
               Get-DBObjectsIntoFolder -server $server -dbname $dbname -DestinationPath $DestinationPath
            .NOTES
                          AUTHOR  : Mark Buckley (mark.c.buckley@navy.mil) 757.396.8821
                     Create DATE  : 11-04-2018
              Last Modified DATE  : 11-04-2018
            .REQUIRES : This script must be run on a box that has SQLServer powershell module loaded
#>


[CmdletBinding(ConfirmImpact="Low")] 
    param(
        [Parameter(Mandatory = $true)][string] $ServerName, # Name of the SQL server to Script out
        [Parameter(Mandatory = $false)][string] $dbname, # Leave BLANK to Script ALL Databases on the server
        [Parameter(Mandatory = $true)][string] $DestinationPath # Where to put scripts
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
                    $LogName = "$($ServerName)_$dbname"
                    $LogFileDir = "$LogFilePath$LogName\"
                    $LogFileName = "$($LogName)_$((Get-Date).tostring("yyyy.MM.dd"))"
                    $LogFileExt = ".txt"
                    $LogFileFullPath = "$LogFileDir$LogFileName$LogFileExt"
                    $LogFile = Enable-LogFile -Path $LogFileFullPath # Turn ON logging
                    ########=~ Script configuration Ends here ~=#################################################
                    #############################################################################################> 
                     # Load Sql.SMO dll    
                    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null
                    $SMOserver = New-Object ('Microsoft.SqlServer.Management.Smo.Server') -argumentlist $server
                    $SMOserver.ConnectionContext.LoginSecure=$false; 
                    $SMOserver.ConnectionContext.set_Login('sa'); 
                    $SMOserver.ConnectionContext.set_Password('Pa$$w)rd123') 
                    $IncludeTypes = @("Tables","StoredProcedures","Views","UserDefinedFunctions", "Triggers") #objects you want do script. 
                    $ExcludeSchemas = @("sys","Information_Schema")
                    $so = new-object ('Microsoft.SqlServer.Management.Smo.ScriptingOptions')
                    
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
                        Write-Debug " - Server: $ServerName"
                        Write-Debug " - dbname: $dbname"
                    }
                  ########################################################################
                  if(!$dbname){$dbs = $SMOserver.databases} else {$dbs=$SMOserver.Databases[$dbname]} #you can change this variable for a query for filter your databases.
                    foreach ($db in $dbs)
                    {
                        $dbname = "$db".replace("[","").replace("]","")
                        $dbpath = "$DestinationPath"+ "\"+"$dbname" + "\"

                        write-host -f cyan "Scritping $dbpath"

                        if ( !(Test-Path $dbpath))
                        {$null=new-item -type directory -name "$dbname"-path "$DestinationPath" -Force}


                    foreach ($Type in $IncludeTypes)
                    {
                        $objpath = "$dbpath" + "$Type" + "\"
                        write-host -f Green "  Scritping $objpath"
                    if ( !(Test-Path $objpath))
                        {$null=new-item -type directory -name "$Type"-path "$dbpath"}
                        foreach ($objs in $db.$Type)
                        {
                                If ($ExcludeSchemas -notcontains $objs.Schema ) 
                                {
                                        $ObjName = "$objs".replace("[","").replace("]","")                  
                                        $OutFile = "$objpath" + "$ObjName" + ".sql"
                                        write-host -f yellow "    Creating file $OutFile"
                                        $objs.Script($so)+"GO" | out-File $OutFile
                                }
                        }
                    }     
                }
                  ########################################################################>   
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

<########################################################################>   
$server = "putrtek-sql"
$dbname = "" # Leave BLANK to Script ALL Databases on the server
$DestinationPath = "C:\Users\putrt\Downloads\powershell\SQL"
Get-DBObjectsIntoFolder -server $server -dbname $dbname -DestinationPath $DestinationPath