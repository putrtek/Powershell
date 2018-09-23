                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         #************RUN AS ADMINISTRATOR****************
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
#"No Administrative rights, it will display a popup window asking user for Admin rights"
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments
break
}





# get operating dir for the script
$ScriptDir = Split-Path $script:MyInvocation.mycommand.path

# Import Modules
Import-Module -Name Microsoft.Powershell.Security
Import-Module Webadministration
Import-Module $ScriptDir\checks.psm1

# Import Ckl
$checklistPath = "$ScriptDir\empty_IIS_Site.ckl"
$ckl = (Select-Xml -Path $checklistPath -XPath /).Node
$stigdata = $ckl.childnodes.stigs.istig.vuln.stig_data
#$vList = $stigdata.attribute_data | where {$_ -like "V-*"}
foreach($a in $stigdata){
    #$a.ParentNode.STIG_DATA
}



# Computername
$computer = 'snnsvr142'  #<--------- Change This

# Checklist output directory
$saveDirectory = "\\snnsvr012\Code 1230\Code 109.33\Cyber Security\STIGs\IIS-Site-STIG-Check-master\$computer\"

# create hastable for export later
$exportTable = @()

# Gets registry key values




#function Set-RuleStatus{}


write-host "start new session"
$session = New-PSSession -ComputerName $computer -Credential nnsy\nn081765wa 


write-host "Invoke commands under new session"
Invoke-Command -Session $session  -ScriptBlock {


# gets the imported module for use by script
write-host "Get modules"
$modules = Get-Module | Where-Object {$_.moduletype -eq 'Script' -and $_.name -like 'checks*'}

# gets all the commands in the module
write-host "Get command list"
$commandlist = $modules.ExportedCommands.values.name | Where-Object {$_ -like 'Get-*'}

    foreach($command in $commandlist)
    {
        # prepares the command to be executed
        $jogatize = (Get-Command $command -CommandType Function).ScriptBlock

        Write-Host("Running $command") -ForegroundColor Yellow
        # running the actual command; feeding it into a variable
        $yourmom = invoke-command $jogatize -ArgumentList $computer

        # get the STIG data corresponding with the vulnerability ID
        $rule = set-cklXml -stigdata $stigdata -vulnID $yourmom.vulnid

        # Set the status field inside the ckl file
        $rule.ParentNode.STATUS = $yourmom.result

        #set the comment field inside the ckl file
        $rule.ParentNode.COMMENTS = $yourmom.comments

        $stigobject = Set-Stigobject -ruletitle $rule.ATTRIBUTE_DATA -vulnID $yourmom.vulnid -result $yourmom.result -value $yourmom.comments
        $exportTable += $stigobject

        $yourmom = $null

    }

    }
 Remove-PSSession $session


# check for the path because if it doesn't exist it can't save because powershell is a crybaby bitch
$testPath = Test-Path $saveDirectory
if($testPath -eq $false){

    New-Item $saveDirectory -type directory

}

# Save the .ckl file with the type of checklist and the computername
$ckl.Save($saveDirectory+ $computer + "_IIS_Site.ckl")

