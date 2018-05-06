function Compress-Subfolders
{
    <#  

     .SYNOPSIS
        This function will zip up files older then a selected date and create a seperate zip for each folder 
        .DESCRIPTION
        Script will mapp a drive to the $SourcePath and then Recurse a diretory and create a seperate zip file for each subfolder 
        Based on Creation Date - Older then the Date passed in. I use this script to backup Apache Tomcat folders prior to Upgrade. 
        Mapping a drive to these folders requires Credentials to be passed.
    .EXAMPLE
        Compress-Subfolders `
        -SourcePath '\\snnsvr321\e$\ReportsInError' `
        -OutputFolder '\\snnsvr092\c1237\R2W\ReportsInError' `
        -ZipFileName "ReportsInError" `
        -Hours 720 `
        -Credentials "nnsy\nn99999"
    .NOTES
                    AUTHOR  : Mark Buckley NNSY C109.33 IT Solutions mark.c.buckley@navy.mil 757.396.8821
               Create DATE  : 04-15-2018
        Last Modified DATE  : 04-20-2018           
                  .REQUIRES : Compress-Archive cmdlet requires POSH v5.0 or higher
    #Requires -Version 5.0 
    #>

    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Low")] 
    param ( 
            [Parameter(Mandatory = $true)][string] $SourcePath,   # Folder where files to be zipped are located 
            [Parameter(Mandatory = $true)][string] $OutputFolder, # Folder where Zip file will go to 
            [Parameter(Mandatory = $true)][string] $ZipFileName,  # Name of Zip file 
            [Parameter(Mandatory = $true)][INT]    $Hours,        # Number of Hours before the current Time set to 0 for ALL files
            [Parameter(Mandatory = $true)][string] $Credentials   # User name  "nnsy\nn99999"
          )

    $cred = get-Credential -credential $Credentials
    New-PSDrive -Name Q -PSProvider FileSystem -Root $SourcePath -Credential $cred -Persist
   
    $subfolders = Get-ChildItem "Q:\" | Where-Object { $_.PSIsContainer }
    ForEach ($folder in $subfolders)
    {
        $path = $folder
        $path
        Set-Location $path.FullName
        $fullpath = $path.FullName
        $pathName = $path.BaseName
        $FileList += $path.FullName

        $CutDay = [DateTime]::Now.AddHours(-$Hours) # Only files OLDER then this date will be archived 
        $items = Get-ChildItem *.* | Where {$_.LastWriteTime -lt $CutDay}

        $zipname = $path.name + ".zip"
        $zippath = "$outputfolder\$zipname"

       <# Write-Host "CutDay: $CutDay"
        Write-Host "folder: $folder"
        Write-Host "fullpath: $fullpath"
        Write-Host "zippath: $zippath"
        write-host $items
        Write-Host "-----------------------------"
        #>

       Compress-Archive -Path $items -DestinationPath $zippath -verbose 
    } 
     cd J:
     Remove-PSDrive Q
}

# Processed Reports - 720 Hours = 30 days
# Compress-Subfolders -SourcePath "\\snnsvr321\Upload\ProcessedReports" -OutputFolder "\\snnsvr092\c1237\R2W\ProcessedReports" -Hours 720

# UnidentifiedReports Reports - 720 Hours = 30 days
# Compress-Subfolders -SourcePath "\\snnsvr321\Upload\UnidentifiedReports" -OutputFolder "\\snnsvr092\c1237\R2W\UnidentifiedReports" -Hours 720

# ReportsInError Reports - 720 Hours = 30 days
# Compress-Subfolders -SourcePath "\\snnsvr321\Upload\ReportsInError" -OutputFolder "\\snnsvr092\c1237\R2W\ReportsInError" -Hours 720
 
# Apache Tomcat Folders - 0 Hours = ALL Files
Compress-Subfolders -SourcePath "\\snnsvr321\c$\Program Files\Apache Software Foundation\Tomcat7-R2W"`
                    -OutputFolder "\\snnsvr092\c1237\R2W\ApacheTomcat" `
                    -ZipFileName "R2W_Tomcat_Backup" `
                    -Hours 0 -Credentials "nnsy\nn087432sa"

 