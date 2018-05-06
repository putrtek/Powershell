Function Compress-Folders ()
	{
	 
	<#
	            .SYNOPSIS
	                script to zip up files to a new folder (use to zip up web site files before updating with new code.
	            .DESCRIPTION
	                script to zip up files in the $SourcePath of a given $extention and the Number of $Hours before the current Time
                    This will zip up the eintre folder structure into a single $ZipName file.
	                Then move ZIP to $ZiPDestination folder 
	            .PARAMETER SourcePath 
	                Full Path to the folder where files you want to zip up are located.
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
	
	       
	[CmdletBinding( DefaultParameterSetName=”SourcePath”, SupportsShouldProcess=$True, ConfirmImpact=’Low’)]
	PARAM(
	        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
	        [ValidateNotNullOrEmpty()]
	        [ValidateScript({Test-Path -PathType container -Path $_})]
	        [STRING[]]$SourcePath,

	        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
	        [ValidateNotNullOrEmpty()]
	        [ValidateScript({Test-Path -PathType container -Path $_})]
	        [STRING[]]$ZiPDestination,
	       
	        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=2)]
	        [ValidateNotNullOrEmpty()]
	        [STRING[]]$ZipName,
	        
	        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=3)]
	        [ValidateNotNullOrEmpty()]
	        [STRING]$Extension,

	        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=4)]
	        [ValidateNotNullOrEmpty()]
	        [int]$Hours #Number of Hours before the current Time Only files OLDER then this date will be archived

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
	        Write-Host -f Green "SourcePath: $SourcePath "
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
	  #   try{
                # Determine what files to archive
                  $AllFilesCount = $(get-childitem $SourcePath -Filter $Extension -Recurse | Where {$_.LastWriteTime -lt $CutDay} |tee -Variable Files | measure).Count
	            # Compress-Archive  -Path $Files -DestinationPath $ZiPDestination\$($ZipName).zip -CompressionLevel Optimal -Verbose
               
	        }# End try
            Write-Host -F Green "processed $AllFilesCount Files that were older then $CutDay"
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
	}# End Process  
} # End Function

# NVR WebSite Folder Archive #########################################################################################
  $SourcePath = "\\snnsvr200\C200\C280\284\NVR\"
  $ZiPDestination = "\\snnsvr012\Code 1230\Code 1237\WebMasters\WebSite Information\Web Application Information\NVR\Code\Backup\" 
  $ZipName = "NVR_StaticWeb_Backup"
  $Extension = "*.*"
  $Hours = 0 # Adjust this number to get to the prior full month (720 hours in a month)

Compress-Folders -SourcePath $SourcePath -ZiPDestination $ZiPDestination -ZipName $ZipName -Extension $Extension -Hours $Hours
###############################################################################################################################>

