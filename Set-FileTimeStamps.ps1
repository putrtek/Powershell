Function Set-FileTimeStamps

{

 Param (

    [Parameter(mandatory=$true)] [string[]]$path,

    [datetime]$date = ("02/15/2016"))

    Get-ChildItem -Path $path |

    ForEach-Object {

     $_.CreationTime = $date
     $_.LastAccessTime = $date
     $_.LastWriteTime = $date }

} #end function 
Set-FileTimeStamps "C:\Users\PUTRTEK\Downloads\PowerShell\ZipScript\reports\2016.02.02"