Function Compress-FilesByMonth ()
	{
	 # Run as ISE with your SA/WA account otherwise the File/Folder Deleteion part will fail with a Access Denied error.
	<#
	            .SYNOPSIS
	                script to zip up files by Year.Month to a new folder then delete original
	            .DESCRIPTION
	                script to zip up R2W files inn the SourcePath of a given extention and the Number of Hours before the current Time
                    This will create a seperate ZIP file for each Year.Month period
	                Then move ZIP to ZiPDestination folder Then delete the original files
	            .PARAMETER SourcePath 
	                Full Path to the folder where files you want to zip up are located.
	            .PARAMETER ZiPDestination
	                Full Path to the folder where ZIP files should go.
	            .PARAMETER ZipName
	                The Name for the zip file - Default name will be the name of the file with a ZIP extention
	            .PARAMETER Extension
	                Extention for the type of file to be ZIPPED ie: ".trc"
	            .EXAMPLE
	                Compress-FilesByMonth -SourcePath $SourcePath -ZiPDestination $ZiPDestination -ZipName $ZipName -Extension $Extension -Hours $Hours
	            .NOTES
	                          AUTHOR  : Mark Buckley NNSY C109.33 IT Solutions mark.c.buckley@navy.mil 757.396.8821 
	                     Create DATE  : 01.01.2017
	              Last Modified DATE  : 04.20.2018
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
	process {
	 try{
	    # Determine what files to archive
        $MyArray = @()
	    $AllFilesCount = $(get-childitem $SourcePath -Filter $Extension -Recurse | Where {$_.LastWriteTime -lt $CutDay} |tee -Variable Files | measure).Count
	    $Files | %{ # get Month and Year of Files in the Array $Files
            $temp='' | Select Filename, period
            $temp.Filename = $_.Fullname
            $temp.Period = '{0:yyyMM}' -f $_.LastWriteTime 
            $MyArray+=$temp
            }
        #$MyArray
        #############################################################################################	         
        if ($MyArray -ne $null)
        {
            foreach($period in ($MyArray | select Period -Unique))
            {
                write-host -f Yellow "#############################=- Processing Files for $($period.Period) Creating ZIP file : $ZiPDestination\$($ZipName)_$($Period.Period).zip -=###############################"
                $MyArray | ?{$_.Period -eq $period.Period} | select -expand Filename | Out-File .\FileList.TXT -Encoding ASCII
               # gc .\FileList.TXT
               Compress-Archive  -Path (gc .\FileList.TXT) -DestinationPath $ZiPDestination\$($ZipName)_$($Period.Period).zip -CompressionLevel Optimal -Verbose
               # now that the files have been added to the zip we can delete the file.
               gc .\FileList.TXT | Remove-Item  -Verbose
            }

            #############################################################################################>
            #############################################################################################
            # Now lets go back and delete the empty folders we just created
             write-host -f Yellow "#############################=- Delete Empty Directoties -=###############################"
            $dirs = get-childitem $SourcePath -Directory -Recurse | Where {(get-childitem $_.Fullname).count -eq 0 } | Select -expand fullname
            $dirs | foreach{remove-item $_ -Force -Verbose}
            #############################################################################################>
        }
        Write-Host -F Green "processed $AllFilesCount Files that were older then $CutDay"

	 }# End TRy
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
	    $LogFile | Disable-LogFile # Turn OFF logging
	  }# End Process  
	} # End Function

<# ProcessedReports Folder Archive #########################################################################################
     $ZipName = "ProcessedReports"
      $SourcePath = "\\snnsvr321\upload\ProcessedReports"
      $ZiPDestination = "\\snnsvr092\c1237\R2W\"
      $Extension = "*.asc"
      $Hours = 900 # Adjust this number to get to the prior full month (720 hours in a month)

	Compress-FilesByMonth -SourcePath $SourcePath -ZiPDestination $ZiPDestination -ZipName $ZipName -Extension $Extension -Hours $Hours
###############################################################################################################################>

<# Reports In Error Folder Archive #########################################################################################
    $ZipName = "ReportsInError"
    $SourcePath = "\\snnsvr321\upload\ReportsInError"
    $ZiPDestination = "\\snnsvr092\c1237\R2W\"
    $Extension = "*.asc"
    $Hours = 900 # Adjust this number to get to the prior full month (720 hours in a month)

    Compress-FilesByMonth -SourcePath $SourcePath -ZiPDestination $ZiPDestination -ZipName $ZipName -Extension $Extension -Hours $Hours
###############################################################################################################################>

<# UnidentifiedReports Folder Archive #########################################################################################
    $ZipName = "UnidentifiedReports"
    $SourcePath = "\\snnsvr321\upload\UnidentifiedReports"
    $ZiPDestination = "\\snnsvr092\c1237\R2W\"
    $Extension = "*.asc"
    $Hours = 900 # Adjust this number to get to the prior full month (720 hours in a month)

    Compress-FilesByMonth -SourcePath $SourcePath -ZiPDestination $ZiPDestination -ZipName $ZipName -Extension $Extension -Hours $Hours
###############################################################################################################################>

<# Log files from 175 bAtCH Folder Archive #########################################################################################
    $ZipName = "175lOGS"
    $SourcePath = "\\snnsvr321\upload\"
    $ZiPDestination = '\\snnsvr092\c1237\R2W\'
    $Extension = "log_*.TXT"
    $Hours = 900 # Adjust this number to get to the prior full month (720 hours in a month)

    Compress-FilesByMonth -SourcePath $SourcePath -ZiPDestination $ZiPDestination -ZipName $ZipName -Extension $Extension -Hours $Hours
###############################################################################################################################>


