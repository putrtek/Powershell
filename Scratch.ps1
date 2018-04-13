function Compress-Subfolders
{
    param
    (
        [Parameter(Mandatory = $true)][string] $SourcePath, # Folder where files to be zipped are located 
        [Parameter(Mandatory = $true)][string] $OutputFolder, # Folder whwre Zip file will go to
        [Parameter(Mandatory = $true)][INT]$Hours  #Number of Hours before the current Time set to 0 for ALL files
    )

    $subfolders = Get-ChildItem $SourcePath | Where-Object { $_.PSIsContainer }

    ForEach ($folder in $subfolders) 
    {
        $path = $folder
        $path
        Set-Location $path.FullName
        $fullpath = $path.FullName
        $pathName = $path.BaseName

        #Get all items 
        $CutDay = [DateTime]::Now.AddHours(-$Hours) # Only files OLDER then this date will be archived
       # $AllFilesCount = $(get-childitem $SourcePath -Filter $Extension -Recurse | Where {$_.LastWriteTime -lt $CutDay} | tee -Variable Files | measure).Count
        #$Files
        $items = Get-ChildItem  *.* | Where {$_.LastWriteTime -lt $CutDay}

        $zipname = $path.name + ".zip"
        $zippath = $outputfolder + $zipname

        #$items
        <#output variables
        Write-output "zippath $zippath"
        Write-output "zipname $zipname"
        Write-output "path Name $pathName"
        Write-output "fullpath $fullpath"
        Write-output "path $path"
        #>
       Compress-Archive -Path $items -DestinationPath $zippath -verbose
    }
}

Compress-Subfolders  -SourcePath "C:\Users\PUTRTEK\Downloads\PowerShell\ZipScript\reports\" `
    -OutputFolder "C:\Users\PUTRTEK\Downloads\PowerShell\ZipScript\reports\Backup\"`
    -Hours 10