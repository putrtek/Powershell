function New-DemoData ($Path) 
{ 
  # This script will create 10 folders, at the target path (provided by the parameter) 
  # and create a random number of *.txt files (between 10 and 200) in each directory, each file between 1KB and 800KB in size.
  # Usage: New-DemoData “D:\Company” 
  
  Push-Location 
  1..9 | % { Set-Location -Path (New-Item -ItemType directory -path "$path\2016.0$_.0$_").fullname -ErrorAction SilentlyContinue 
  for ( $i=1; $i -le (Get-Random -Minimum 10 -Maximum 200); $i++ ) 
    { 
      fsutil file createnew ("File" + $i + ".txt") (Get-Random -Minimum 1024 -Maximum 819200) 
    } #>
  } 
  Pop-Location 
}

New-DemoData 'C:\Users\PUTRTEK\Downloads\PowerShell\ZipScript\reports'

