function New-DemoData ($Path, $folder) 
{ 
  # This script will create 10 folders, at the target path (provided by the Path parameter)  ie: 2013.01.01
  # and create a random number of *.txt files (between 10 and 200) in each directory, each file between 1KB and 800KB in size.
  # It will also set the LastWriiten date to the folder name
  # Usage: New-DemoData 'D:\Company' '2013'
  Push-Location 
  1..9 | % { #write-host "$path\$Folder.0$_.0$_"
    Set-Location -Path (New-Item -ItemType directory -path "$path\$Folder.0$_.0$_").fullname -ErrorAction SilentlyContinue 
  for ( $i=1; $i -le (Get-Random -Minimum 10 -Maximum 200); $i++ ) 
    { 
     #write-host "File$i.txt"
      New-Item -Name "File$i.txt" -ItemType file #-LastAccessTime "$Folder.0$_.0$_" -CreationTime "$Folder.0$_.0$_" -lastwritetime
    } #>
    foreach($file in Get-ChildItem -path "$path\$Folder.0$_.0$_") 
    #{write-host $file.Fullname}
    {$(Get-Item $file.Fullname).lastwritetime="$Folder.0$_.0$_"}
  } 
  Pop-Location 
}

New-DemoData 'C:\Users\PUTRTEK\Downloads\PowerShell\ZipScript\reports' '2013'

