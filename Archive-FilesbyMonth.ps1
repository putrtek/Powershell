Function Archive-FilesByMonth{
    param(
        [string]$archivefolder,
        [string]$archivemonths
        )
    $cutoffdate = (Get-Date -Hour 0 -Minute 0 -Second 0 -Day 1).AddMonths(-$archivemonths)
    write-host $cutoffdate
    $myarray=@()
    gci $archivefolder -exclude *.zip | ?{$_.LastWriteTime -lt $cutoffdate} | %{
    #record the month & year of the files in an array
	$temp='' | Select Filename,Period
        $temp.Filename=$_.FullName
        $temp.Period='{0:MMyyyy}' -f $_.LastWriteTime
        $myarray+=$temp
	}
 #Get each unique month/year from the array
foreach($period in ($myarray | Select Period -unique)){
        $myarray | ?{$_.Period -eq $period.period} | Select -expand FileName | out-file .\filelist.txt -encoding ASCII
	$argumentlist="a -tzip $($archivefolder)\$($period.period).zip @.\filelist.txt"
        $result=start-process 'C:\Program Files\7-Zip\7z.exe' -argumentlist $argumentlist -NoNewWindow -wait
        write-host $result
      #  gc .\filelist.txt | %{gci $_} | %{$_.Delete()}
        }
}

        
Archive-FilesByMonth -archivefolder 'C:\Users\PUTRTEK\Downloads\PowerShell\ZipScript\reports'  -archivemonths 2