function Set-ReturnObject{ 
    PARAM($vulnid,$comments,$result)   
    $returnObject = New-Object psobject -Property @{
        vulnid = $vulnid
        comments = $comments
        result = $result
    }
    return $returnObject
}


function Get-RegKey{
    param(
            [string]$path, [string]$computer, [string]$hive, [string]$value
        )
    $path = $path.TrimStart('\')
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hive, $computer)
    $key = $reg.OpenSubKey($path)
    if(!$value){
        return $key
    } else{
        $result = $key.GetValue($value)
        return $result
    }
}

function Set-Stigobject{
    Param($ruletitle,$vulnID,$value,$result)
    $object = New-Object -TypeName PSObject
    $object | Add-Member –MemberType NoteProperty –Name RuleTitle –Value "$ruletitle"
    $object | Add-Member –MemberType NoteProperty –Name VulnID –Value "$vulnID"
    $object | Add-Member –MemberType NoteProperty –Name Value –Value "$value"
    $object | Add-Member -MemberType NoteProperty –Name Result –Value "$result"
    return $object
}

function Set-CklXml{
    Param($stigdata,$vulnID)
    
    $check = $stigdata | Where-Object {$_.attribute_data -like $vulnID}
    $rule = $check.parentnode.STIG_DATA | Where-Object {$_.vuln_attribute -like 'Rule_Title'}
    #$object = New-Object -TypeName PSObject
    #$object | Add-Member –MemberType NoteProperty –Name VULN_ATTRIBUTE –Value $rule.
    return $rule
}
function Get-13620 ()
{
	 <#
    .SYNOPSIS
        Function to retrun values for STIG item V13620
    .DESCRIPTION
        WG355 - A private web-site must utilize certificates from a trusted DoD CA.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-V13620 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>

     [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )
    
    # Set the current vulnID
    $vulnID = 'V-13620'

    # Script start
    Import-Module WebAdministration

    # get list of sites
    $sites = Get-Website

    # get ssl bindings 
    $sslSites = Get-ChildItem IIS:\SslBindings | Where-Object {$_.port -eq '443'} 

    # get just the thumbprints from the site certs
    $thumbprints = $sslSites | ForEach-Object {$_.thumbprint}

    #get certs
    $certs = Get-ChildItem CERT:LocalMachine/My | Where-Object {$thumbprints -contains $_.thumbprint}

    # collect results <-- probably a better way to do this***
    $results = @()
    foreach($k in $certs){

        if($k.getissuername() -match '(CA\W)' -or $k.subject -match $computer){
            $result = 'NotAFinding' 
            $results += $result
        }
        else{
            $result = 'Open'
            $results += $result
        }
    }

    # check result table
    $asdf = $results -match 'Open'

    # checking to see if there are any matches, indicating a noncompliant value
    if($asdf.count -gt 0){
        $resultObject = 'Open'
    }else{
        $resultObject = 'NotAFinding'
    }


    #create object to capture results and relevant info for STIG viewer
    $returnObject = New-Object psobject -Property @{
        vulnid = ''
        comments = ''
        result = ''
    }


    #comment if necessary
    $returnObject.comments = 'Only machine certs are present outside of RWCP'
    $returnObject.vulnid = $vulnID
    $returnObject.result = $resultObject

    return $returnObject



}

function Get-3333
{
	 <#
    .SYNOPSIS
        Function to retrun values for STIG item V3333
    .DESCRIPTION
        WG205 - The web document (home) directory must be in a separate partition from the web server’s system files.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-3333 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
    [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer 
    )
    # 
    # V-3333
    #
    $vulnid = 'V-3333'

    #get list of websites
    $k = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module Webadministration
        Get-Website
        #return $sites
    } 

    foreach($item in $k){
        $flag = $false

        #check to see if sites are based on the system drive
        if($item.physicalPath.Contains('C:\') -or $item.physicalPath.Contains('%SystemDrive%')){
            $flag = $true
        }

        if($flag = $true){
            $result = 'Open'
        }else{
            $result = 'NotAFinding'

        }
    }

    $object = Set-ReturnObject -vulnid $vulnid -comments $k.ToString() -result $result

    return $object
}#>

function Get-3963
{
	<#
    .SYNOPSIS
        Function to retrun values for STIG item V3963
    .DESCRIPTION
        WA000-WI070 - Indexing Services must only index web content.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-3963 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
    [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )
    
    $vulnid = 'V-3963'

    # Checking for the existence of regkey
    $check = get-regKey -hive localmachine -path \SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs\ -computer $computer
    #$check = get-regKey -hive localmachine -path \SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\ -computer $env:Computername

    if($null -eq $check){
        $result = 'NotAFinding'
        $check = 'Regkey does not exist'

    }else{
        $result = 'Open'
        $check = 'Regkey exists'
    }

    $object = Set-ReturnObject -vulnid $vulnid -comments $check -result $result

    return $object

}

function Get-6373
{
   <#
    .SYNOPSIS
        Function to retrun values for STIG item 6373
    .DESCRIPTION
      WG265  The required DoD banner page must be displayed to authenticated users accessing a DoD private website.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-6373 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
    [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )

    $vulnid = 'V-6373'

    # This requires input from the BTS staff
    $result = 'Open'
    $comment = 'BTS developers input required'

    $object = Set-ReturnObject -vulnid $vulnid -comments $comment -result $result

    return $object
}

function Get-6531
{
	<#
    .SYNOPSIS
        Function to retrun values for STIG item 6531
    .DESCRIPTION
        WG140 - A private web-sites authentication mechanism must use client certificates.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-6531 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )

    # 
    # V-6531 A private web-sites authentication mechanism must use client certificates.
    #
    $vulnid = 'V-6531'

    # hash for collecting values
    $k = @()
    $k = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module WebAdministration
        $sites = Get-Website

        # hash to capture objects
        $pHash = @()
        foreach ($item in $sites)
        {
            $pObject = New-Object psobject -Property @{
                sitename = ''
                sslflags = ''
            }
            $siteName = $item.name
            $webBinding = Get-WebBinding -Name $sitename | Where-Object protocol -eq 'https'
            if($null -ne $webBinding)
            {
            
                $configProp = Get-WebConfigurationProperty -Filter /system.webserver/security/access -Location $sitename -name '*'
                #$configProp |Get-Member $configProp.sslflags
                $pObject.sitename = $siteName
                $pObject.sslflags = $configProp.sslflags
                $pHash += $pObject     
        
            }
        }

        $pHash
    
    }

    $flag = $false
    foreach ($item in $k)
    {
        if ($item.sslflags -notmatch 'Require' )
        {
            $flag = $true
            $comments = 'its broke' #<--- Fix this
        }else{
            #nothing
        }
    
    
    }

    if ($flag -eq $false)
    {
        $result =  'NotAFinding'
    }else{
        $result = 'Open'
    }

    # create object to return values for ckl
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result

    return $object
}

function Get-6724
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 6724
    .DESCRIPTION
        WG520 - All web-sites must be assigned a default Host header.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-6724 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )

    $vulnid = 'V-6724'

    #array sorta
    $localSite = @()
    $localSite = Invoke-Command -ComputerName $computer -ScriptBlock {
    
        $sitehash = @()

        $sites = Get-Website
        $sites | ForEach-Object {
            $siteobject = New-Object psobject -Property @{
                sitename = ''
                bindingport = ''
                hostHeader = ''
                count = ''
                result = ''
            }
            $dammit = Get-WebBinding -Name $_.name

            $siteobject.hostHeader = $dammit.bindinginformation | ForEach-Object{$_.split(':')[-1]}
            $siteobject.bindingport = $dammit.bindinginformation | ForEach-Object{$_.split(':')[-2]}
            $siteobject.sitename = $_.name
            $siteobject.result = $siteobject.hostHeader -eq ''
            $sitehash += $siteobject
        }

        return $sitehash

    
    }


    $flag = $false
    foreach ($i in $localsite)
    {
        if ($i.hostheader.Count -gt 1)
        {
            foreach ($t in $i.hostHeader)
            {
                if($t -eq '')
                {
                    $flag = $true
                }
            }
    
        }else{
            if($i.hostHeader -eq ''){
                $flag = $true
            }
    
        }
  
    }


    if ($flag -eq $true)
    {
        $result = 'Open'
        $comments = 'No host header present'
    }else{
        $result = 'NotAFinding'
        $comments = 'Host header present or N/A'
    }

    # create object to return values for ckl
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result

    return $object
}

function Get-6755
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 6724
    .DESCRIPTION
        WA000-WI090 - Directory Browsing must be disabled.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-6724 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )
    
    $vulnid = 'V-6755'

    $jogatize = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module WebAdministration

        #get sites
        $sites = Get-Website

        $flag = $false

        $sites | ForEach-Object {
            $sitename = $_.name
            $mong = Get-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -PSPath "IIS:\Sites\$sitename"
            if($mong.value -eq $true){
                $flag = $true
            }
        

        }

        return $flag

    }


    if($jogatize -eq $true)
    {
        $result = 'Open'
    }
    else{
        $result = 'NotAFinding'
    }

    # create object to return values for ckl
    $object = Set-ReturnObject -vulnid $vulnid -comments '' -result $result
    
    return $object
}

function Get-13686
{
	<#
    .SYNOPSIS
        Function to retrun values for STIG item 13686
    .DESCRIPTION
       WG235 - Remote authors or content providers will only use secure encrypted logons and connections to upload files to the Document Root directory.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13686 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
    [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )
    $vulnid = 'V-13686'

    $result = 'NotAFinding'

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments 'Remote uploading is not being performed.' -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13688
{
	<#
    .SYNOPSIS
        Function to retrun values for STIG item 13688
    .DESCRIPTION
       WG242 - Log files must consist of the required data fields.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13688 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
    [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )
    $vulnid = 'V-13688'
    $returned = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module WebAdministration
        #get list of sites
        $sites = Get-Website

        # create object used to collect log info
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.Web.Administration')
        $iis = New-Object Microsoft.Web.Administration.ServerManager

        # table to hold values
        $table = @()


        ##This can be done better@'
        # loop thru sites to check log PARAMeters
        foreach($s in $sites){
    
            # create object to insert into table
            $stats = New-Object psobject -Property @{
                site_name = ''
                logfile_enabled = ''
                fields = ''
                result = ''
                comments = ''
            }

            #add sitename to object
            $stats.site_name = $s.name

            # get iis properties for $s
            $web = $iis.Sites[$s.name]

            #check for logfile enabled PARAMeter
            $stats.logfile_enabled = $web.logfile.Enabled

            $fields = $web.LogFile.LogExtFileFlags

            # add fields to object
            $stats.fields = $fields

            # check to see if the require fields are being logged
            if ($fields -like '*ProtocolVersion*' -and
                $fields -like '*ClientIp*' -and
                $fields -like '*UserName*' -and
                $fields -like '*date*' -and
                $fields -like '*time*' -and
                $fields -like '*method*' -and
                $fields -like '*uriquery*' -and
                $fields -like '*referer*' -and
                $fields -like '*httpstatus*' -and
                $fields -like '*httpstatus*' -and
            $fields -like '*httpstatus*')
            {
                $stats.result = 'NotAFinding'
            }else{
                $stats.result = 'Open'
            }
            $table += $stats
      
        }
        return $table
    }


    # find the open result values
    $openCount = $returned | Where-Object {$_.result -eq 'Open'}

    # find the count of false object values
    $disabledCount = $returned | Where-Object {$_.logfile_enabled -eq $false }

    # check for the count of both
    if($openCount.count -ge 1 -or $disabledCOunt.count -ge 1){
        $result = 'Open'
    }else{
        $result = 'NotAFinding'
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $returned.fields.value.tostring() -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13689
{
	<#
    .SYNOPSIS
        Function to retrun values for STIG item 13689
    .DESCRIPTION
       WG255 - Access to the web-site log files must be restricted.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13689 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
     [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )

    $vulnid = 'V-13689'

    # remotely invoke command
    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock{
        
        #create object to store results
        $return = New-Object psobject -Property @{
            accounts = ''
            result = ''
        }
    
        # get acl of IIS logs
        $logfileACL = Get-Acl 'c:\inetpub\logs\LogFiles'

        # check for the allowed users/groups and expose non compliance
        $logfileACL | ForEach-Object{
            $weird = $_.access | Where-Object{$_.identityreference -notmatch 'Administrators' -and $_.identityreference -notmatch 'SYSTEM' -and $_.identityreference -notmatch 'TrustedInstaller'} 
        }

        if($null -ne $weird)
        {
            $result = 'Open'
        }else{
            $result = 'NotAFinding'
        }

        $mong = $weird | ForEach-Object{$_.identityreference.value}

        $return.accounts = $mong -join ' '
        $return.result = $result

        return $return
    }    

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $invReturn.accounts -result $invReturn.result
    
    #return object for use in parent script
    return $object


}

function Get-13694
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13694
    .DESCRIPTION
       WG342 - Public web servers must use TLS if authentication is required.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13694 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )

    $vulnid = 'V-13694'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
    
        Import-Module webadministration

        # get all websites
        $sites = get-website

        # get only ssl sites
        $sites = $sites | Where-Object{$_.bindings.collection -match ':443'}

        #hashtable for sites
        $table = @()

        # Loop thru sites for sslflags
        foreach ($s in $sites)
        {
            $configProp = Get-WebConfigurationProperty -Filter /system.webserver/security/access -Location $s.name -name '*'
  
            # create object to hold ssl flag values
            $stats = New-Object psobject -Property @{
                site_name = ''
                sslflags = ''
                result = ''

            }


            $sitename = $s.name
            
            # set sitenames ans sslflag results
            $stats.site_name = $sitename
            $stats.sslflags = $configProp.sslflags
            
            # check for requirecert value
            if($stats.sslflags -match 'ssl128'){
                $stats.result = 'NotAFinding'
            }else{
                $stats.result = 'Open'
            }

            # add object to hash
            $table +=$stats
        }


        return $table

        <#if(($table -match 'Open').count -gt 0){
                $result = 'Open'
                }else{
                $result = 'NotAFinding'
                }
        #>
    }

    if(($invReturn -match 'Open').count -gt 0){
        $result = 'Open'
    }else{
        $result = 'NotAFinding'
    }

    $comments = ($invReturn | Where-Object{$_.result -eq 'Open'} | ForEach-Object{$_.site_name}) -join ' '

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments  -result $result
    
    #return object for use in parent script
    return $object



}

function Get-13702
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13702
    .DESCRIPTION
       WA000-WI120 - The Content Location header must not contain proprietary IP addresses.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13702 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )

    $vulnid = 'V-13702'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module webadministration 

        # get websites
        $sites = Get-Website

        #create array to hold objects
        $table = @()

        foreach($s in $sites){
            $sitename = $s.name

            $kObject = New-Object psobject -Property @{
                sitename = ''
                alternateHostName = ''
            }

            try{
                $configprop = Get-WebConfigurationProperty -Filter /system.webserver/serverRuntime -Location $sitename -Name '*'

                # create object to collect serverRuntime info


                $kObject.sitename = $sitename
                $kObject.alternateHostName = $configprop.alternateHostName
            }
            catch{
                $kObject.sitename = $sitename
                $kObject.alternateHostName = 'Error encountered while retrieving PARAMeter.'
            }
            $table += $kObject
        }

        # get blank alternatehostname entries
        $blank = $table | Where-Object{$_.alternatehostname -eq ''}



        #return object for compliance determination
        return $blank
    }

    if($null -ne $invreturn -or $blank -ne '')
    {
        $result = 'Open'
        $comments = $invreturn.sitename -join ' '
        #need to add site names for comment
    }else{
        $result = 'NotAFinding'
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13703
{
	 <#
    .SYNOPSIS
        Function to retrun values for STIG item 13703
    .DESCRIPTION
       WA000-WI6010 - The website must have a unique application pool.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13703 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
    [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )

    # V-13703 The website must have a unique application pool.
    $vulnid = 'V-13703'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        Import-Module webadministration

        $sites = get-website

        $appPools = @()
        foreach($s in $sites){
            $appPools += $s.applicationpool
        }

        # select only unique application pools
        $r = $appPools | Select-Object -Unique

        $comp = Compare-Object -ReferenceObject $r -DifferenceObject $appPools

        return $comp
    }

    if($null -ne $invReturn.inputobject){
        $result = 'Open'
        $comments = $invReturn.inputobject -join ' '
    }else{
        $result = 'NotAFinding'
        $comments = ''
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13704
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13704
    .DESCRIPTION
       WA000-WI6020 -  The application pool must have a recycle time set.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13704 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )

    # V-13704
    $vulnid = 'V-13704'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
    ####
    # Code goes here
    ####
    }

    $result = 'Not_Reviewed'

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13705
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13705
    .DESCRIPTION
       WA000-WI6022 - The maximum number of requests an application pool can process must be set.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13705 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]$computer
    )

    $vulnid = 'V-13705'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #PARAMeter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-WebConfiguration $applicationPoolsPath -Location IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    requestLimitValue = $appPool.applicationPoolDefaults.recycling.periodicRestart.requests  

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.requestlimitvalue -ne 0}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }




    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13706
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13706
    .DESCRIPTION
       WA000-WI6024 - The amount of virtual memory an application pool uses must be set.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13706 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
		$computer
    )

    # V-13706
    $vulnid = 'V-13706'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #PARAMeter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-WebConfiguration $applicationPoolsPath -Location IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    virtualMemoryLimit = $appPool.applicationPoolDefaults.recycling.periodicRestart.memory

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.virtualMemoryLimit -eq 0}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }




    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13707
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13707
    .DESCRIPTION
       WA000-WI6026 - The amount of private memory an application pool uses must be set.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13707 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

    # V-13707
    $vulnid = 'V-13707'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
        #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #PARAMeter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-WebConfiguration $applicationPoolsPath -Location IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    privateMemoryLimit = $appPool.applicationPoolDefaults.recycling.periodicRestart.privatememory

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.privateMemoryLimit -eq 0}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }




    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13708
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13708
    .DESCRIPTION
       WA000-WI6028 - The Idle Timeout monitor must be enabled.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13708 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

    # V-13708
    $vulnid = 'V-13708'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
         #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #PARAMeter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    idleTimeout = $appPool.processModel.idleTimeout.Minutes

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.idleTimeout -gt 20}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }




    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object


}

function Get-13709
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13709
    .DESCRIPTION
       WA000-WI6030 - The maximum queue length for HTTP.sys must be managed.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13709 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

    # V-13709
    $vulnid = 'V-13709'

        $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
         #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #PARAMeter being measured
        $applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    queueLength = $appPool.queueLength

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.queueLength -gt 1000}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13710
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13710
    .DESCRIPTION
       WA000-WI6032 - An application pool’s pinging monitor must be enabled.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13710 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

    # V-13710
    $vulnid = 'V-13710'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

         #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #PARAMeter being measured
        #$applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    pingEnabled = $appPool.processModel.pingingEnabled

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.processModel.pingingEnabled -eq $false}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13712
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13712
    .DESCRIPTION
       WA000-WI6036 - An application pool’s rapid fail protection settings must be managed.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13712 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

    # V-13712
    $vulnid = 'V-13712'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

                 #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #PARAMeter being measured
        #$applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    rapidFailProtection = $appPool.failure.rapidFailProtection

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | where-Object{$_.rapidFailProtection -eq $false}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-13713
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 13713
    .DESCRIPTION
       WA000-WI6040 - The application pool identity must be defined for each web-site.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-13713 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

    # V-13713
    $vulnid = 'V-13713'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

                                 #import IIS module
        import-module webadministration

        #get list of application pools
        $pools = get-childitem IIS:\AppPools  

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #PARAMeter being measured
        #$applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($p in $pools){

                #retrieve requestlimit value
                #"dis"
                $name = $p.name
                $appPool = Get-ItemProperty -Path IIS:\AppPools\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    AppPoolName = $p.name
                    identityType = $appPool.processModel.identityType

                }

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable

    }

    $comp = $invReturn | Where-Object{$_.identityType -notmatch 'amed\\(.*)\.[^\s]+|ApplicationPoolIdentity|network(.*)'}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        $comments = $comp.appPoolname -join '; '
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-15334
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 15334
    .DESCRIPTION
       WG610 -  Web sites must utilize ports, protocols, and services according to PPSM guidelines.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-15334 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

    # V-15334
    $vulnid = 'V-15334'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
    
                                               #import IIS module
        import-module webadministration

        #get list of application pools
        $sites = get-childitem IIS:\sites\

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #PARAMeter being measured
        #$applicationPoolsPath = "/system.applicationHost/applicationPools"

        #$appPool.applicationPoolDefaults.processModel

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($s in $sites){

                #retrieve sites
                #"dis"
                $name = $s.name
                $sitesInfo = Get-ItemProperty -Path IIS:\sites\$name

                #'dat'
                # create psobject and add result to it
                $object = New-Object PSObject -Property @{
                    sitename = $s.name
                    bindings = $s.bindings.Collection | foreach-object{$_.bindinginformation} | out-string

                }

                #remove ip addresses, host headers, newline, and asterisks
                $object.bindings = $object.bindings -replace "[a-z]|\.|\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\*|`n",""

                #add object to hashtable
                $hashTable += $object

        }

        return $hashTable


    }

    #comparison is excluding port 80 and 443 sites
    $comp = $invReturn | where-object{$_.bindings -notmatch ":80:|:443:"}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.bindings}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26011
{
	<#
    .SYNOPSIS
        Function to retrun values for STIG item 26011
    .DESCRIPTION
		WA000-WI6140 -  Debug must be turned off on a production website.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-26011 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
   PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26011
    $vulnid = 'V-26011'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        #import IIS module
        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

            #get list of application pools and retrieve requestlimit PARAMeter
            foreach($o in $sites){

                $sitename = $o.name
    
                $compilation = Get-WebConfigurationProperty -Filter "/system.web/compilation" -Location IIS:\sites\$sitename -name '*'
                $compilation = $compilation.attributes | Where-Object{$_.name -match 'debug'}

                $object = New-Object PSObject -Property @{
                    sitename = $o.name
                    compDebug = $compilation.value

                }

                $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.compDebug -notmatch $false}

    if($null -eq $computer){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.compDebug}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}
#
function Get-26026
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 26026
    .DESCRIPTION
		WA000-WI6180 -  The production web-site must utilize SHA1 encryption for Machine Key.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-26026 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26026
    $vulnid = 'V-26026'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        #import IIS module
        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

            #get list of application pools and retrieve requestlimit PARAMeter
            foreach($o in $sites){

                $sitename = $o.name
    
                $machineKey = Get-WebConfigurationProperty -Filter "/system.web/machineKey" -Location IIS:\sites\$sitename -name '*'

                $object = New-Object PSObject -Property @{
                    sitename = $o.name
                    machineKey = $machineKey.validation
                }

                $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.machinekey -notmatch 'SHA1'}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.machinekey}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26031
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 26031
    .DESCRIPTION
		WA000-WI6165 -   The production web-site must be configured to prevent detailed HTTP error pages from being sent to remote clients.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-26031 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26031
    $vulnid = 'V-26031'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($o in $sites){

            $sitename = $o.name
    
            $eMode = get-WebConfiguration -Filter "/system.webServer/httpErrors" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                emode = $emode.errormode
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.emode -notmatch 'DetailedLocalOnly' -or $_.emode -notmatch 'Custom'}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.emode}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26034
{
	<#
    .SYNOPSIS
        Function to retrun values for STIG item 26034
    .DESCRIPTION
		WA000-WI6200 -  The production web-site must configure the Global .NET Trust Level.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-26034 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
     [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26034
    $vulnid = 'V-26034'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($o in $sites){

            $sitename = $o.name
    
            $secPol = get-WebConfiguration -Filter "/system.web/trust" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                secpol = $secpol.level
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.secpol -match 'High' -or $_.secpol -match 'Full'}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.secpol}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26041
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 26041
    .DESCRIPTION
		WA000-WI6210 - The web-site must limit the number of bytes accepted in a request.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-26041 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26041
    $vulnid = 'V-26041'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

    import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfiguration -Filter "/system.webserver/security/requestfiltering/requestlimits" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                maxAllowedContentLength = $request.maxAllowedContentLength
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.maxAllowedContentLength -notmatch 30000000}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.secpol}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26042
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 26042
    .DESCRIPTION
		WA000-WI6220 -  The production web-site must limit the MaxURL.
    .PARAMETER computer Name 
    .EXAMPLE 
      Get-26042 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26042
    $vulnid = 'V-26042'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

    import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfiguration -Filter "/system.webserver/security/requestfiltering/requestlimits" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                maxUrl = $request.maxUrl
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.maxUrl -notmatch 4096}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.maxUrl}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26043
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 26043
    .DESCRIPTION
		WA000-WI6230 -   The production web-site must configure the Maximum Query String limit.
    .PARAMETER computer Name 
    .EXAMPLE 
		Get-26043 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26043
    $vulnid = 'V-26043'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {

        import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfiguration -Filter "/system.webserver/security/requestfiltering/requestlimits" -Location IIS:\sites\$sitename

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                maxQueryString = $request.maxQueryString
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.maxQueryString -notmatch 2048}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.maxUrl}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26044 ()
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 26044
    .DESCRIPTION
		WA000-WI6230 - The web-site must not allow non-ASCII characters in URLs.
    .PARAMETER computer Name 
    .EXAMPLE 
		Get-26044 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    
	
	[CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26044
    $vulnid = 'V-26044'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
       import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters"

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                allowHighBitCharacters = $request.value
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.allowHighBitCharacters -notmatch $false}

    if($comp -eq $null){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.allowHighBitCharacters}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26045
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 26045
    .DESCRIPTION
		WA000-WI6250 - The web-site must not allow double encoded URL requests.
    .PARAMETER computer Name 
    .EXAMPLE 
		Get-26045 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26045
    $vulnid = 'V-26045'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
       import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping"

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                allowDoubleEscaping = $request.value
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.allowDoubleEscaping -notmatch $false}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding bother site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.allowDoubleEscaping}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-26046
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 26046
    .DESCRIPTION
		WA000-WI6260 -  The production web-site must filter unlisted file extensions in URL requests.
    .PARAMETER computer Name 
    .EXAMPLE 
		Get-26046 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-26046
    $vulnid = 'V-26046'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
       import-module webadministration

        #get list of application pools
        $sites = Get-ChildItem -Path IIS:\sites

        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($o in $sites){

            $sitename = $o.name
    
            $request = get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site'  -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted"

            $object = New-Object PSObject -Property @{
                sitename = $o.name
                allowUnlisted = $request.value
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    #ensuring the value for debug = false
    $comp = $invReturn | where-object{$_.allowUnlisted -notmatch $false}

    if($null -eq $comp){
        $result = 'NotAFinding'
        $comments = ''
    }else{
        $result = 'Open'
        
        # adding other site names and port bindings for clarity
        $comments = $comp | foreach-object{$_.sitename + " " + $_.allowUnlisted}
        $comments = $comments -join '; '
        
    }

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}#>

function Get-2267
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 2267
    .DESCRIPTION
		WA000-WI050 - Unapproved script mappings in IIS 7 must be removed.
    .PARAMETER computer Name 
    .EXAMPLE 
		Get-2267 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-2267
    $vulnid = 'V-2267'


    $result = 'Open'
        
    $comments = 'Handler blacklist must be created'

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}

function Get-2263
{
    <#
    .SYNOPSIS
        Function to retrun values for STIG item 2263
    .DESCRIPTION
		WG350 - A private web server must have a valid server certificate.
    .PARAMETER computer Name 
    .EXAMPLE 
		Get-2263 "snnsvr181"
     .NOTES 
        AUTHOR : NNSY C109.33 IT Solutions 
        Create DATE : 09.20.2018
        Last Modified DATE : 09.20.2018
    #>
	
	 [CmdletBinding( DefaultPARAMeterSetName="Computer", ConfirmImpact='Low')] 
	PARAM
    (
        [String][PARAMeter(Mandatory=$true)]
        $computer
    )

        # V-2263
    $vulnid = 'V-2263'

    $invReturn = Invoke-Command -ComputerName $computer -ScriptBlock {
      
      #get local cert store
      $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
      $store.Open("ReadOnly")
      $certs = $store.Certificates


        #create hashtable to hold objects for analysis
        $hashTable = @()

        #get list of application pools and retrieve requestlimit PARAMeter
        foreach($c in $certs){


            $object = New-Object PSObject -Property @{
                subject = $c.Subject.ToString()
                issuer = $c.Issuer.ToString()
            }

            $hashtable += $object
            

        }

        return $hashTable


    }

    # Open because most servers do no have DoD issued certs
    $result = 'Open'
    
    # List out the certs on the server    
    $comments = $invReturn | ForEach-Object{"Subject: "+ $_.subject + "`n" + "Issuer: " + $_.issuer + "`n"}
        

    # set findings in return object
    $object = Set-ReturnObject -vulnid $vulnid -comments $comments -result $result
    
    #return object for use in parent script
    return $object
}