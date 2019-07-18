# Author: Fırat Akcan
# akcan.firat |at| gmail |dot| com
# 2019

function Get-Hotfixes {
	LogMe
	
	$outputs = Invoke-Expression "wmic qfe list"
	$outputs = $outputs[1..($outputs.Length)]

	foreach ($output in $outputs) {
		if ($output) {
			$output = $output -replace 'y U','y-U'
			$output = $output -replace 'NT A','NT-A'
			$output = $output -replace '\s+',' '
			$parts = $output -split ' '
			$Dateis = $null
			if ($parts[5] -like "*/*/*") {
				$Dateis = [datetime]::ParseExact($parts[5],'%M/%d/yyyy',[Globalization.cultureinfo]::GetCultureInfo("en-US").DateTimeFormat)
			} 
			elseif (($parts[5] -eq $null) -or ($parts[5] -eq '')) {
				$Dateis = [datetime]1700
			}
			else {
				$Dateis = Get-Date ([datetime][Convert]::ToInt64("$parts[5]",16)) -Format '%M/%d/yyyy'
			}
			
			New-Object -Type PSObject -Property @{
				KBArticle = [string]$parts[0]
				Computername = [string]$parts[1]
				Description = [string]$parts[2]
				FixComments = [string]$parts[6]
				HotFixID = [string]$parts[3]
				InstalledOn = Get-Date ($Dateis) -Format "dddd d MMMM yyyy"
				InstalledBy = [string]$parts[4]
				InstallDate = [string]$parts[7]
				Name = [string]$parts[8]
				ServicePackInEffect = [string]$parts[9]
				Status = [string]$parts[10]
			}
		}
	}
}

function MakeAndChangeDirectory {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		$Path
	)
	LogMe
	
	New-Item -Path $Path -ItemType Directory
	Set-Location -Path $Path
}

function Test-Alias {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe
	
	if((Test-Path "alias:$Name")){ return $true }
	return $false
}

function Get-EnvironmentValue {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe
	
	return (Get-Item env:$Name).Value
}

function Convert-CmdVariable2PoShVariable {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe
	
	$reg = [regex]::new('%\w+%')	
	$results = $reg.Matches($Name).Value
	if($results)
	{
		foreach($result in $results)
		{
			$variable = $result
			$rVariable = $variable.Replace('%','')
			$Name = $Name.Replace( $variable, (Get-Item env:$rVariable).Value )
		}
		return (Convert-CmdVariable2PoShVariable $Name)
	}
	return $Name
}

function Add-PSSnapinIfNotYetAdded {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe

	if ((Get-PSSnapin | Where-Object { $_.Name -eq $Name }) -eq $null) {
		if (Check-PSSnapinAvailable $Name) {
			Add-PSSnapin $Name
			Write-Verbose "$Name Snapin added"
		}
		else {
			Write-Host "You cannot add $Name Snapin since it is not installed on local computer" -foreground red
		}
	}
	else {
		Write-Verbose "$Name Snapin is already added"
	}
}

function Check-PSSnapinAvailable {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe

	if ((Get-PSSnapin -Registered $Name) -ne $null) {
		return $True
	}
	return $False
}

function Import-ModuleIfNotYetImported {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe

	if ((Get-Module | Where-Object { $_.Name -eq $Name }) -eq $null) {
		if (Check-ModuleAvailable $Name) {
			Import-Module $Name
			Write-Verbose "$Name module imported."
		}
		else {
			Write-Host "You cannot add $Name module since it is not installed on local computer" -foreground red
		}
	}
	else {
		Write-Verbose "$Name module is already imported :)"
	}
}

function Check-ModuleAvailable {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe

	if ((Get-Module -ListAvailable | Where-Object { $_.Name -eq $Name} ) -ne $null) {
		return $True
	}
	return $False
}

function Run-PSasAdmin {
	LogMe
	
	if (!(Test-AmIAdmin))
	{
		Write-Warning -Message "You should allow the prompted screen to open a PowerShell window has administrator rights!"
		$cmd = "powershell.exe"
		$arguments = "-NoLogo " #-ExecutionPolicy Bypass"
		Start-Process $cmd -Verb runas -ArgumentList $arguments
	}
	else
	{
		Write-Host "You have already administrator rights :)" -ForegroundColor Red
	}
}

function Test-AmIAdmin {
	LogMe
	
	if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
	{
		return $false
	}
	return $true
}

function Run-CommandAsAdmin {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Command
	)
	LogMe
	
	if (!(Test-AmIAdmin))
	{		
		if ($Command.EndsWith(".ps1"))
		{
			Start-Process powershell.exe -ArgumentList "-noexit -NoLogo -File $Command" -Verb RunAs
		}
		else
		{
			Start-Process powershell.exe -Verb RunAs -ArgumentList "-noexit -NoLogo -Command ""Run-CommandAsAdmin `'$Command`' """
		}
	}
	else
	{
		Write-Host "PS >" $Command -ForegroundColor Yellow
		Invoke-Expression -Command $Command
	}
}

function Set-As {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe
	
	New-PSDrive -PSProvider FileSystem -Name $Name -Root . -Scope Global | Out-Null
	Set-Location -LiteralPath "$($name):"
}

function Create-Shortcut {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true,
			HelpMessage = "Enter a valid exe path",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string] $Application,
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Enter a valid path where you want to create the shortcut.",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 1
		)]
		[ValidateNotNullOrEmpty()]
		[string] $Path
	)
	LogMe
	
	$appName = (Get-Item $Application).BaseName
	$Shell = New-Object -ComObject WScript.Shell
	$Shortcut = $Shell.CreateShortcut((Join-Path -Path $Path -ChildPath ($appName + ".lnk")))
	$Shortcut.TargetPath = $Application
	$Shortcut.Save()
	Write-Verbose "Shortcut created."
}

function Add-ScheduledTask {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true,
			HelpMessage = "Enter a valid XML file path",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string] $XMLFile,
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Enter a task name",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 1
		)]
		[string] $TaskName = $null	
	)
	LogMe
	
	if((Test-Path -Path $XMLFile) -and ($XMLFile.EndsWith(".xml")))
	{
		$taskExists = Get-ScheduledTask | ? { $_.TaskName -like $TaskName }
		if($taskExists)
		{
			Write-Host "$TaskName already exists" -foreground yellow
		}
		else
		{
			if((String-IsNullOrEmpty $TaskName))
			{
				$TaskName = (Get-Item $XMLFile).BaseName
				$taskExists = Get-ScheduledTask | ? { $_.TaskName -like $TaskName }
			}			
			if($taskExists)
			{
				Write-Host "$TaskName already exists" -foreground yellow				
			}			
			else
			{
				Register-ScheduledTask -Xml (Get-Content $XMLFile | out-string) -TaskName $TaskName | out-null
				Enable-ScheduledTask -TaskName $TaskName
			}
		}
	}
	else
	{
		Write-Host "There is no valid XML file." -foreground red
	}
}

function Delete-ScheduledTask {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Enter a task name",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 1
		)]
		[ValidateNotNullOrEmpty()]
		[string] $TaskName
	)
	LogMe
	
	$taskExists = Get-ScheduledTask | ? { $_.TaskName -like $TaskName }
	if($taskExists)
	{
		Disable-ScheduledTask -TaskName $TaskName | out-null
		Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false | out-null
		Write-Host "$TaskName is deleted" -foreground yellow
	}
	else
	{
		Write-Host "There is no task like $TaskName" -foreground red
	}
}

function String-IsNullOrEmpty {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true,
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[AllowEmptyString()]
		[string] $Value = $null
	)
	LogMe
	
	return [string]::IsNullOrEmpty($Value)
}

function Get-SystemService {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe
	
	return Get-Service | ? { $_.Name -like $Name } | % { [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; Status = $_.Status; StartType = $_.StartType; DependentServices = $_.DependentServices; RequiredServices = $_.RequiredServices; ServiceType = $_.ServiceType; } }
}

function Get-SystemServices {
	LogMe
	
	return Get-Service | % { [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; Status = $_.Status; StartType = $_.StartType; DependentServices = $_.DependentServices; RequiredServices = $_.RequiredServices; ServiceType = $_.ServiceType; } }
}

function Get-DetailedInfoAboutScheduledTasks {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true,
			HelpMessage = "You may use wildcard character to extend your search criteria. e.g: '*name*' or 'name*' or '*name'",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string] $Name
	)
	LogMe
	
	$tasks = Get-ScheduledTask | ? { $_.TaskName -like $name }
	$detailedTasks = $tasks | % {
		[pscustomobject]@{
			Server = $env:COMPUTERNAME
			Name = $_.TaskName
			Path = $_.TaskPath
			Description = $_.Description
			Author = $_.Author
			RunAsUser = $_.Principal.userid
			LastRunTime = $(($_ | Get-ScheduledTaskInfo).LastRunTime)
			LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
			NextRun = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
			Status = $_.State
			Command = $_.Actions.execute
			Arguments = $_.Actions.Arguments 
		}
	}
	
	$taskCounter = 0
	$str = ""
	$detailedTasks | % {
		$taskCounter = $taskCounter + 1
		$str += "`nTask $taskCounter"
		$str += "`n "
		$_.PSObject.Properties | % {
			$str += ("`n   {0,-15}: {1}" -f $_.Name, $_.Value)
		}
		$str += "`n"		
	}
	Write-Verbose $str
	return $detailedTasks
}

function Switch-ScheduledTaskState {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true,
			HelpMessage = "Enter task name",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string] $Name,
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Enable, Disable",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 1
		)]
		[ValidateSet('Enable','Disable')]
		[string]$Option
	)
	LogMe
	
	$tasks = Get-ScheduledTask -TaskName $Name
	$task = $tasks[0]
	if($Option -ne $null -and $Option -ne "")
	{
		if($Option -eq "Enable")
		{
			if($task.State -eq "Disabled")
			{
				Enable-ScheduledTask -TaskName $task.TaskName | out-null
			}
		}
		else
		{
			if($task.State -ne "Disabled")
			{
				Disable-ScheduledTask -TaskName $task.TaskName | out-null
			}
		}
	}
	else
	{
		if($task.State -eq "Disabled")
		{
			Enable-ScheduledTask -TaskName $task.TaskName | out-null
		}
		else
		{
			Disable-ScheduledTask -TaskName $task.TaskName | out-null
		}
	}
	$ntask = Get-ScheduledTask -TaskName $task.TaskName
	Write-Host "$($ntask.TaskName) state: $($ntask.State)" -ForegroundColor yellow
}

function Get-IISLogDirectories {
	LogMe
	
	Import-ModuleIfNotYetImported WebAdministration
	
	$result = (Get-WebSitesByURLorName -Url * | Select ID, Name, Logfile | Sort-Object ID -Unique )
	Write-Host $result
	return $result
}

function Get-WebSitesByURLorName {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Enter the web site/s' URL. To get all, write '*'",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string[]] $Url,
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Enter the web site/s' name. To get all, write '*'",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 1
		)]
		[ValidateNotNullOrEmpty()]
		[string[]] $Name
	)	
	LogMe
	
	if(-not ($Url -or $Name)){
		Write-Host "You have to pass an argument at least one of 'Url' or 'Name'" -foreground Red
		return
	}
	if(!(Test-AmIAdmin))
	{
		Write-Host "You need to have the administrator rights to get the result!" -foreground Red
		$cUrl = ""
		$cName = ""
		if($Url){ 
			$str = ""
			foreach($u in $Url) { 
				$str += "''$u''," 
			}
			$str = $str.Substring(0,$str.Length-1)
			$cUrl = "-Url $str" 
		}
		if($Name){ 
			$str = ""
			foreach($n in $Name) { 
				$str += "''$n''," 
			}
			$str = $str.Substring(0,$str.Length-1)
			$cName =  "-Name $str" 
		}
		Run-CommandAsAdmin -Command "Get-WebSitesByURLorName $cUrl $cName"
		return
	}
	Import-ModuleIfNotYetImported WebAdministration
	
	$webs = Get-Website | % {
		[pscustomobject]@{ 
			ID = $_.ID; 
			Name = $_.Name; 
			State = $_.State;
			Logfile = Join-Path -Path $_.Logfile.Directory.replace("%SystemDrive%",$env.SystemDrive) -ChildPath ("W3SVC" + $_.ID );
			Path = $_.physicalPath;
			AppPool = $_.applicationPool;
			URL = @($_.Bindings.Collection.BindingInformation | % { $_.Split(":")[-1] }) 
		}
	} | % { $fID = $_.ID; $fName = $_.Name; $fState = $_.State; 
			$fLogfile = $_.Logfile; $fPath = $_.Path; $fAppPool = $_.AppPool; $_.URL | % {
			[pscustomobject]@{ 
				URL = $_;
				ID = $fID; 
				Name = $fName;
				State = $fState;
				Logfile = $fLogfile;
				Path = $fPath;
				AppPool = $fAppPool;
			}
		}
	}
	if($Name -eq "*")
	{
		$namedFounded = $webs
	}
	else
	{
		$namedFounded = $webs | ? { $n = $_.Name; ($Name | ? { $n -eq $_  }) }
	}
	Write-Verbose ($namedFounded | out-string)
	if($Url -eq "*")
	{
		$urlsFounded = $webs
	}
	else
	{
		$urlsFounded = $webs | ? { $u = $_.URL; ($Url | ? { $u -eq $_  }) }
	}
	Write-Verbose ($urlsFounded | out-string)
	$results = @()
	$results += $urlsFounded
	$results += $namedFounded 
	return ($results | Sort-Object URL -Unique)
}

function Recycle-AppPoolsByURLorName {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Enter the web site/s' URL. To recycle all, write '*'",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string[]] $Url,
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Enter the web site/s' name. To recycle all, write '*'",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 1
		)]
		[ValidateNotNullOrEmpty()]
		[string[]] $Name,
		[switch] $WithoutInteraction
	)
	LogMe
	
	if(-not ($Url -or $Name)){
		Write-Host "You have to pass an argument at least one of 'Url' or 'Name'" -foreground Red
		return
	}
	if(!(Test-AmIAdmin))
	{
		Write-Host "You need to have the administrator rights to recycle web application pools!" -foreground Red
		$cUrl = ""
		$cName = ""
		if($Url){ 
			$str = ""
			foreach($u in $Url) { 
				$str += "''$u''," 
			}
			$str = $str.Substring(0,$str.Length-1)
			$cUrl = "-Url $str" 
		}
		if($Name){ 
			$str = ""
			foreach($n in $Name) { 
				$str += "''$n''," 
			}
			$str = $str.Substring(0,$str.Length-1)
			$cName =  "-Name $str" 
		}
		switch ($WithoutInteraction.IsPresent) {
			$false {
				Run-CommandAsAdmin -Command "Recycle-AppPoolsByURLorName $cUrl $cName"
			}
			$true {
				Run-CommandAsAdmin -Command "Recycle-AppPoolsByURLorName -WithoutInteraction $cUrl $cName"
			}
		}		
		return
	}
	
	Import-ModuleIfNotYetImported WebAdministration
	
	$getWebSites = @()
	if($Url) {
		$getWebSites += (Get-WebSitesByURLorName -Url $Url)
	}
	if($Name) {
		$getWebSites += (Get-WebSitesByURLorName -Name $Name)
	}
	
	$results = ($getWebSites | Sort-Object URL -Unique  | Select ID, Name, AppPool | Group-Object AppPool)		

	foreach($result in $results) { 		
		$appPool = $result.Name
		switch ($WithoutInteraction.IsPresent) {
			$false {
				$str = "`n"
				$counter = 1
				$result.Group | Sort-Object Name -Unique | % { 
					$str += "$counter) $($_.Name)`n"
					$counter += 1
				}
				$str = "`nIf you recycle $appPool, these web sites will be affected.`n" + $str
				Write-Host $str -foreground White
				$reply = Read-Host -Prompt "Continue? [y/n]"
				if($reply -match "[yY]") {				
					Restart-WebAppPool $appPool
					Write-Host $appPool "is recycled" -foreground Green
				}
				else {
					Write-Host $appPool "isn't recycled" -foreground Red
				}
			}
			$true {
				Restart-WebAppPool $appPool
				Write-Host $appPool "is recycled" -foreground Green
			}
		}
	}	
}

function Test-RegistryValue { 
	[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the registry key where the value should be set.  Will be created if it doesn't exist.
        $Path,
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the value being set.
        $Name
    )
	LogMe
	
	if(Get-Member -InputObject (Get-ItemProperty -Path $Path) -Name $Name) 
	{
		return $true
	}
	return $false
}

function Get-RegistryValue {
	[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the registry key where the value should be set.  Will be created if it doesn't exist.
        $Path,
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the value being set.
        $Name
    )
	LogMe
	
	return (Get-ItemProperty -Path $Path -Name $Name).$Name
}

function Add-WebSites2Localhost {
	LogMe
	
	Import-ModuleIfNotYetImported WebAdministration
	
	$hostsfile = Join-Path -Path $env:SystemRoot -ChildPath "System32\drivers\etc\hosts"
	$date = Get-Date -UFormat "%y%m%d%H%M%S"
	$filecopy = $hostsfile + '.' + $env:USERNAME + '.' + $date + '.copy'
	Copy-Item $hostsfile -Destination $filecopy

	$hosts = Get-WebBinding | % { $_.bindingInformation.Split(":")[-1] } | Select-Object -Unique

	$file = Get-Content $hostsfile
	$file = $file | Out-String

	$hosts | % {
		if ($file.Contains($_)) {
			Write-Host "Entry for $_ already exists. Skipping"
		}
		else {
			Write-Host "Adding entry for $_";
			Add-Content -Path $hostsfile -Value "127.0.0.1 `t $_ "
		}
	}
	# Disable the loopback check, since everything we just did will fail if it's enabled
	$regPath = HKLM:\System\CurrentControlSet\Control\Lsa
	$regName = DisableLoopbackCheck
	if(-not (Test-RegistryValue -Path $regPath -Name $regName))
	{
		New-ItemProperty $regPath -Name $regName -Value 1 -PropertyType dword
	}
	else
	{
		$val = (Get-RegistryValue -Path $regPath -Name $regName)
		if($val -ne 1)
		{
			Set-ItemProperty $regPath -Name $regName -Value 1 -PropertyType dword
		}
	}
}

function Zip {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true,
			HelpMessage = "Enter file/directory path",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string] $Path
	)
	LogMe
	
	$szip = (Join-Path -Path $env:CustomApps -ChildPath "7-Zip\7z.exe")
	if(Test-Path -Path $Path -PathType Leaf)
	{
		$zipPath = $Path.Substring(0, $Path.Length - (Get-Item $Path).Extension.Length)
		& $szip -mx9 a ($zipPath + ".zip") $Path | out-null
		Get-ChildItem ($zipPath + ".zip")
	}
	elseif(Test-Path -Path $Path -PathType Container)
	{		
		$zipPath = $Path
		if($Path.EndsWith("\"))
		{
			$zipPath = $Path.Substring(0, $Path.Length - 1)
		}
		& $szip -mx9 a ($zipPath + ".zip") $Path | out-null
		Get-ChildItem ($zipPath + ".zip")
	}
	else
	{
		Write-Host "There is no file or directory to zip it!" -foreground red
	}
}

function Unzip {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true,
			HelpMessage = "Enter zip file path",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string] $ZipPath,
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Enter a path where zip file is going to be extracted.",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 1
		)]
		[string] $Path = ""
	)
	LogMe
	
	if((Test-Path -Path $ZipPath) -and ($ZipPath.EndsWith(".zip")))
	{
		$szip = (Join-Path -Path $env:CustomApps -ChildPath "7-Zip\7z.exe")
		
		$extractedPath = $null
		if(-not (String-IsNullOrEmpty $Path))
		{
			if(Test-Path -Path $Path -PathType Container)
			{
				$extractedPath = $Path
			}
			else
			{
				$extractedPath = Join-Path -Path (Get-Item $ZipPath).Directory -ChildPath (Get-Item $ZipPath).BaseName
				New-Item -Path $extractedPath -ItemType Directory | out-null
				Write-Host "$Path is not valid, $extractedPath is going to be used to extract." -foreground Yellow
			}
		}
		else
		{
			$extractedPath = Join-Path -Path (Get-Item $ZipPath).Directory -ChildPath (Get-Item $ZipPath).BaseName
			New-Item -Path $extractedPath -ItemType Directory | out-null
		}
		$option = "-o{0}" -f $extractedPath
		& $szip x $zipPath $option | out-null
		Get-ChildItem $extractedPath
	}
	else
	{
		write-host "There is no zip file to unzip it!" -foreground red
	}
}

function LogMe {
	$CallStack = (Get-PSCallStack).Command
	$Args = (Get-PSCallStack).Arguments
	if($CallStack.Count -ge 1) {
		$CallerFunc = $CallStack[1]
		$Arg = $Args[1]
		$fqdnHostname = $env:COMPUTERNAME + "." + $env:USERDNSDOMAIN
		$User = $env:USERNAME
		$elevated = if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {"Yes"} else {"No"}
		$Message = "Function: $CallerFunc`r`nArguments: $Arg`r`nUser: $User`r`nElevated Powershell Console: $elevated`r`nHost: $fqdnHostname`r`n`r`n$User called $CallerFunc within Easy-Peasy module at $fqdnHostname"
		Write-EventLog -LogName "Windows PowerShell" -Source "Easy-Peasy" -EntryType Information -EventID 0 -Message $Message
	}
}

function Listen-Port {
	<#
	.DESCRIPTION
	Temporarily listen on a given port for connections dumps connections to the screen - useful for troubleshooting
	firewall rules.

	.PARAMETER Port
	The TCP port that the listener should attach to

	.EXAMPLE
	PS C:\> Listen-Port 443
	Listening on port 443, press CTRL+C to cancel

	DateTime                                      AddressFamily Address                                                Port
	--------                                      ------------- -------                                                ----
	3/1/2016 4:36:43 AM                            InterNetwork 192.168.20.179                                        62286
	Listener Closed Safely
	#>
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $true,
			HelpMessage = "Enter the port number",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string] $Port = 80
	)
	LogMe
	
	$endpoint = New-Object System.Net.IPEndPoint ([system.net.ipaddress]::any,$Port)
	$listener = New-Object System.Net.Sockets.TcpListener $endpoint
	$listener.Server.ReceiveTimeout = 3000
	$listener.start()
	try {
		Write-Host "Listening on port $port, press CTRL+C to cancel"
		while ($true) {
			if (!$listener.Pending())
			{
				Start-Sleep -Seconds 1;
				continue;
			}
			$client = $listener.AcceptTcpClient()
			$client.client.RemoteEndPoint | Add-Member -NotePropertyName DateTime -NotePropertyValue (Get-Date) -Passthru
			$client.Close()
		}
	}
	catch {
		Write-Error $_
	}
	finally {
		$listener.stop()
		Write-Host "Listener Closed Safely"
	}

}

function Test-IPPort {
	param(		
		[Parameter(
			Mandatory = $true,
			HelpMessage = "Enter hosts with comma seperated",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[string[]] $Hosts,
		[Parameter(
			Mandatory = $true,
			HelpMessage = "Enter ports with comma seperated",
			ValueFromPipeline = $true,
			ValueFromPipelinebyPropertyName = $true,
			Position = 1
		)]
		[ValidateNotNullOrEmpty()]
		[int[]] $Ports
	)
	LogMe
	
	foreach ($ihost in $Hosts) {
		foreach ($iport in $Ports) {
			$text = "Connecting to $ihost on port $iport...`t"
			try {
				$socket = New-Object System.Net.Sockets.TcpClient ($ihost,$iport)
				$text = $text + "Connected"
				Write-Output $text
			}
			catch [Exception]{
				$text = $text + "Unable to connect"
				Write-Output $text
				Write-Verbose $_.Exception.GetType().FullName
				Write-Verbose $_.Exception.Message
			}
		}
	}
}

function Get-OSVersion {
	LogMe
	
	$WinVer = New-Object -TypeName PSObject
	Add-Member -InputObject $WinVer -MemberType NoteProperty -Name Name -Value ((Get-WmiObject Win32_OperatingSystem).Caption)
	Add-Member -InputObject $WinVer -MemberType NoteProperty -Name Major -Value (Get-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" -Name "CurrentMajorVersionNumber")
	Add-Member -InputObject $WinVer -MemberType NoteProperty -Name Minor -Value (Get-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" -Name "CurrentMinorVersionNumber")
	Add-Member -InputObject $WinVer -MemberType NoteProperty -Name Build -Value (Get-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuild")
	Add-Member -InputObject $WinVer -MemberType NoteProperty -Name Revision -Value (Get-RegistryValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" -Name "UBR")
	return $WinVer
}

function Get-MyAllConsoleHistory {
	[CmdletBinding()]
	param(
		[Parameter(
			Mandatory = $false,
			Position = 0
		)]
		[ValidateNotNullOrEmpty()]
		[int] $First,
		[Parameter(
			Mandatory = $false,
			Position = 1
		)]
		[ValidateNotNullOrEmpty()]
		[int] $Last
	)
	LogMe
	Import-ModuleIfNotYetImported PsReadLine
	
	$content = @()
	
	if ($First) {
		$content += ((Get-Content (Get-PSReadlineOption).HistorySavePath) | Select -First $First)
	}
	if ($Last) {
		$content += ((Get-Content (Get-PSReadlineOption).HistorySavePath) | Select -Last $Last)
	}
	
	if($content.count -ne 0) {
		return $content
	}
	
	return (Get-Content (Get-PSReadlineOption).HistorySavePath)
}

function DoParallel-OnServers {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[array]$Servers,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[ScriptBlock]$Command,
		[Parameter(Mandatory = $false)]
		[PSCredential]$Credential,
		[Parameter(Mandatory = $false)]
		[int]$Timeout = 60
	)
	LogMe
	
	$watch = [System.Diagnostics.StopWatch]::StartNew()	
	[array]$result = @()
	$Servers | % {
		if($Credential -ne $null) {
			$tmp = Fill-ScriptBlockWithArguments -Command {param($Credential) Invoke-Command -ComputerName {0} -Credential $Credential -ScriptBlock {{1}}} -Arguments @($_, $Command)
			$res = (Start-JobInProcess -ScriptBlock $tmp -ArgumentList $Credential -Name ("JobOn_"+$_))
		}
		else {
			$tmp = Fill-ScriptBlockWithArguments -Command {Invoke-Command -ComputerName {0} -ScriptBlock {{1}}} -Arguments @($_, $Command)
			$res = (Start-JobInProcess -ScriptBlock $tmp -Name ("JobOn_"+$_))
		}
		$result += $res
	}
	$timeoutCounter = 1
	$rTimeout = 0
	while( $result.Count -ne ($result | ? { $_.State -eq "Completed"}).Count ){
		$waitingfor = $result | ? {$_.State -ne "Completed"} | % { $_.Name.Replace("JobOn_","") }
		Write-Host ("{0} Waiting for {1}" -f [char]9830, (ConvertTo-String -Array $waitingfor))
		Start-Sleep -Seconds $timeoutCounter
		$rTimeout += $timeoutCounter
		if($rTimeout -gt $Timeout) {
			$str = ""
			$result | ? { $_.State -ne "Completed"} | % { $str += (", {0}" -f $_.Name.Replace("JobOn_","")) }
			if($str.Length -gt 2) {
				$str = $str.Substring(2)
			}
			Write-Host -Foreground Red "Timeout Exception for $str"
			break
		}
		$timeoutCounter++
	}
	[array]$report = @()
	$arrow = "{0}{1}{2}" -f [char]9584, [char]9830, [char]9588
	$result | % {
		$job = $_
		if($job.State -eq "Completed"){ 			
			try{				
				$jobResult = "Completed`t" + (Receive-Job $job -ErrorAction Stop | Out-String)
			}
			catch {				
				$jobResult = "Failed: " + $_.Exception.Message
			}
			$report += ("`n{0}:`n{1} {2}" -f $job.Name.Replace("JobOn_",""), $arrow, $jobResult )
		}
		else {
			$report += ("`n{0}:`n{1} {2}" -f $job.Name.Replace("JobOn_",""), $arrow, $_.Jobstateinfo.State)
		}
	}
	$result | Remove-Job	
	$watch.Stop()	
	$report += ("`nCompleted {0} jobs in {1} seconds." -f $result.Count, $watch.Elapsed.TotalSeconds )
	return $report
}

function ConvertTo-String {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.Array]$Array
	)
	LogMe
	
	$count = $Array.Count
	if($count -eq 1) {
		return $Array[0]
	}
	$str = $Array[-2] + " and " + $Array[-1]
	$tmp = ""
	for($i = 0; $i -lt $count - 2; $i++){
		$tmp += $Array[$i] + ", "
	}
	return ($tmp + $str)
}

function ConvertTo-PlainText {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Security.Securestring]$secure
	)
	LogMe
	
    $marshal = [Runtime.InteropServices.Marshal]
    $marshal::PtrToStringAuto( $marshal::SecureStringToBSTR($secure) )
}

function Get-HostProperties {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[String]$ComputerName = "localhost"
	)
	LogMe
	
	$Asset = New-Object -TypeName PSObject
		
	$allDisks = Get-WmiObject -Class win32_logicaldisk -ComputerName $ComputerName | % { 
		New-Object -TypeName PSObject @{FreeDiskSpace=[Math]::Round($_.FreeSpace /1GB); TotalDiskSize=[Math]::Round($_.Size /1GB); Disk=$_.DeviceID}
	}
	
	$proccessor = Get-WmiObject -Class win32_computersystem -ComputerName $ComputerName | % { [ordered]@{ PhysicalProcessors = $_.NumberofProcessors; LogicalProcessors = $_.NumberOfLogicalProcessors; TotalPhysicalMemory = [Math]::Round($_.TotalPhysicalMemory /1GB)} }
	$os = Get-WmiObject -Class win32_operatingsystem -ComputerName $ComputerName | % { @{ OperatingSystem = $_.Name.Split("|")[0] } }
	
	#$Asset | Add-Member -MemberType NoteProperty -Name Disks -value $allDisks
	$Asset | Add-Member -NotePropertyMembers $proccessor -TypeName Processor
	$Asset | Add-Member -NotePropertyMembers $os -TypeName OS
	
	return $Asset
}

function New-LogEntry {
<#
	.SYNOPSIS
		Function to create a log file for PowerShell scripts
	
	.DESCRIPTION
		Function supports both writing to a text file (default), sending messages only to console via ConsoleOnly parameter or both via WriteToConsole parameter.
		
		The BufferOnly parameter will not write message neither to console or logfile but save to a temporary buffer which can then be piped to file or printed to screen.
	
	.PARAMETER logMessage
		A string containing the message PowerShell should log for example about current action being performed.
	
	.PARAMETER WriteToConsole
		Writes the log message both to the log file and the interactive
		console, similar to built-in Write-Host.
	
	.PARAMETER logFilePath
		Specifies the path and log file name that will be created.
		
		Parameter only accepts full path IE C:\MyLog.log
	
	.PARAMETER isErrorMessage
		Prepend the log message with the [Error] tag in file and
		uses the Write-Error built-in cmdlet to throw a non terminating
		error in PowerShell Console
	
	.PARAMETER IsWarningMessage
		Prepend the log message with the [Warning] tag in file and
		uses the Write-Warning built-in cmdlet to throw a warning in
		PowerShell Console
	
	.PARAMETER ConsoleOnly
		Print the log message to console without writing it file
	
	.PARAMETER BufferOnly
		Saves log message to a variable without printing to console
		or writing to log file
	
	.PARAMETER SaveToBuffer
		Saves log message to a variable for later use
	
	.PARAMETER NoTimeStamp
		Suppresses timestamp in log message
	
	.EXAMPLE
		Example 1: Write a log message to log file
		PS C:\> New-LogEntry -LogMessage "Test Entry"
		
		This will simply output the message "Test Entry" in the logfile
		
		Example 2: Write a log message to console only
		PS C:\> New-LogEntry -LogMessage "Test Entry" -ConsoleOnly
		
		This will print Test Entry on console
		
		Example 3: Write an error log message
		New-LogEntry -LogMessage "Test Log Error" -isErrorMessage
		
		This will prepend the [Error] tag in front of
		log message like:
		
		[06-21 03:20:57] : [Error] - Test Log Error
	
	.NOTES
		Additional information about the function.
#>
	[CmdletBinding(
		ConfirmImpact = 'High',
		PositionalBinding = $true,
		SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[AllowNull()]
		[Alias('Log','Message')]
		[string]$LogMessage,
		[Alias('Print','Echo','Console')]
		[switch]$WriteToConsole = $false,
		[AllowNull()]
		[Alias('Path','LogFile','File','LogPath')]
		[string]$LogFilePath,
		[Alias('Error','IsError','WriteError')]
		[switch]$IsErrorMessage = $false,
		[Alias('Warning','IsWarning','WriteWarning')]
		[switch]$IsWarningMessage = $false,
		[Alias('EchoOnly')]
		[switch]$ConsoleOnly = $false,
		[switch]$BufferOnly = $false,
		[switch]$SaveToBuffer = $false,
		[Alias('Nodate','NoStamp')]
		[switch]$NoTimeStamp = $false
	)
	LogMe
	
	# Don't do anything on empty Log Message
	if ([string]::IsNullOrEmpty($logMessage) -eq $true) {
		return
	}
	# Use script path if no filepath is specified
	if (([string]::IsNullOrEmpty($logFilePath) -eq $true) -and (!($ConsoleOnly))) {
		$logFilePath = $PSCommandPath + '-LogFile-' + $(Get-Date -Format 'yy-MM-dd') + '.log'
	}	
	# Format log message
	if (($isErrorMessage) -and (!($ConsoleOnly))) {
		if ($NoTimeStamp) {
			$tmpMessage = "[Error] - $logMessage"
		}
		else {
			$tmpMessage = "[$(Get-Date -Format 'MM-dd-yy hh:mm:ss')] : [Error] - $logMessage"
		}
	}
	elseif (($IsWarningMessage -eq $true) -and (!($ConsoleOnly))) {
		if ($NoTimeStamp) {
			$tmpMessage = "[Warning] - $logMessage"
		}
		else {
			$tmpMessage = "[$(Get-Date -Format 'MM-dd-yy hh:mm:ss')] : [Warning] - $logMessage"
		}
	}
	else {
		if (!($ConsoleOnly)) {
			if ($NoTimeStamp) {
				$tmpMessage = $logMessage
			}
			else {
				$tmpMessage = "[$(Get-Date -Format 'MM-dd-yy hh:mm:ss')] : $logMessage"
			}
		}
	}
	# Write log messages to console
	if (($ConsoleOnly) -or ($WriteToConsole)) {
		if ($IsErrorMessage) {
			Write-Error $logMessage
		}
		elseif ($IsWarningMessage) {
			Write-Warning $logMessage
		}
		else {
			Write-Output -InputObject $logMessage
		}
		# Write to console and exit
		if ($ConsoleOnly -eq $true) {
			return
		}
	}
	# Write log messages to file
	if (([string]::IsNullOrEmpty($logFilePath) -eq $false) -and ($BufferOnly -ne $true)) {
		$paramOutFile = @{
			InputObject = $tmpMessage
			FilePath = $LogFilePath
			Append = $true
			Encoding = 'utf8'
		}
		Out-File @paramOutFile
	}
	# Save message to buffer
	if (($BufferOnly -eq $true) -or ($SaveToBuffer -eq $true)) {
		$script:messageBuffer += $tmpMessage + '`r`n'
		# Remove blank lines
		$script:messageBuffer = $script:messageBuffer -creplace '(?m)^\s*\r?\n',''
	}
}

function CopyTo-AsParallel {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[array]$Servers,
		[Parameter(Mandatory = $true,HelpMessage = "Enter a valid path on source server to copy necessary files")]
		[ValidateNotNullOrEmpty()]
		[string]$SourcePath,
		[Parameter(Mandatory = $true,HelpMessage = "Enter a valid path on destination server to copy necessary files")]
		[ValidateNotNullOrEmpty()]
		[string]$DestinationPath,
		[Parameter(Mandatory = $false)]
		[PSCredential]$Credential,
		[Parameter(Mandatory = $false)]
		[switch]$UseDefaultAuthentication,
		[Parameter(Mandatory = $false)]
		[switch]$SimplexCopy,
		[Parameter(Mandatory = $false)]
		[int]$Timeout = 180
	)
	LogMe
	
	switch ($SimplexCopy.IsPresent) {
		$false {
			$Command = {
				$sourceSession = New-PSSession -ComputerName {0} -Credential $using:Credential
				Copy-Item -FromSession $sourceSession -Path {1} -Destination {2} -Recurse
			}
			if($Credential){ 
				$cred = $Credential
			}
			else {
				throw "You have to use Credential parameter when you don't use 'UseDefaultAuthentication' switch!"
			}
			
			if($UseDefaultAuthentication.IsPresent) {
				$Command = {
					$sourceSession = New-PSSession -ComputerName {0}
					Copy-Item -FromSession $sourceSession -Path {1} -Destination {2} -Recurse
				}
				$cred = $null
			}	
			
			$tmp = Fill-ScriptBlockWithArguments -Command $Command -Arguments @((Get-HostName -FQDN), $SourcePath, $DestinationPath)
			#$Command = {
			#	$sourceSession = New-PSSession -ComputerName {computername}
			#	Copy-Item -FromSession $sourceSession -Path {path} -Destination {destination} -Recurse
			#}
			#$tmp = Fill-TemplateWithArguments -Template $Command -Keywords @{'computername'=(Get-HostName -FQDN); 'path'=$SourcePath; 'destination'= $DestinationPath}			
			DoParallel-OnServers -Servers $Servers -Credential $cred -Timeout $Timeout -Command $tmp
		}
		$true {
			$watch = [System.Diagnostics.StopWatch]::StartNew()
			$arrow = "{0}{1}{2}" -f [char]9584, [char]9830, [char]9588
			$result = @()
			$Servers | % {
				$Command = {
					$destinationSession = New-PSSession -ComputerName {0}
					Copy-Item -ToSession $destinationSession -Path {1} -Destination {2} -Recurse
				}				
				if($Credential){ 
					$Command = {
						$destinationSession = New-PSSession -ComputerName {0} -Credential $Credential
						Copy-Item -ToSession $destinationSession -Path {1} -Destination {2} -Recurse
					}
				}
				$tmp = Fill-ScriptBlockWithArguments -Command $Command -Arguments @($_, $SourcePath, $DestinationPath)
				$result += (Start-JobInProcess -ScriptBlock $tmp -Name ("CopyJob_" + $_) )
			}
			$timeoutCounter = 1
			$rTimeout = 0
			while( $result.Count -ne ($result | ? { $_.State -eq "Completed"}).Count ){
				$waitingfor = $result | ? {$_.State -ne "Completed"} | % { $_.Name.Replace("CopyJob_","") }
				Write-Host ("{0} Waiting for {1}" -f [char]9830, (ConvertTo-String -Array $waitingfor))
				Start-Sleep -Seconds $timeoutCounter
				$rTimeout += $timeoutCounter
				if($rTimeout -gt $Timeout) {
					$str = ""
					$result | ? { $_.State -ne "Completed"} | % { $str += (", {0}" -f $_.Name.Replace("CopyJob_","")) }
					if($str.Length -gt 2) {
						$str = $str.Substring(2)
					}
					Write-Host -Foreground Red "Timeout Exception for $str"
					break
				}
				$timeoutCounter++
			}
			[array]$report = @()
			$arrow = "{0}{1}{2}" -f [char]9584, [char]9830, [char]9588
			$result | % {
				$job = $_
				if($job.State -eq "Completed"){ 			
					try{				
						$jobResult = "Completed`t" + (Receive-Job $job -ErrorAction Stop | Out-String)
					}
					catch {				
						$jobResult = "Failed: " + $_.Exception.Message
					}
					$report += ("`n{0}:`n{1} {2}" -f $job.Name.Replace("CopyJob_",""), $arrow, $jobResult )
				}
				else {
					$report += ("`n{0}:`n{1} {2}" -f $job.Name.Replace("CopyJob_",""), $arrow, $_.Jobstateinfo.State)
				}
			}
			$result | Remove-Job
			$watch.Stop()	
			$report += ("`nCompleted {0} jobs in {1} seconds." -f $result.Count, $watch.Elapsed.TotalSeconds )
			return $report
		}
	}
}

function Create-ScriptBlockWithArguments {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$Command,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[array]$Arguments
	)
	LogMe
	
	$str = $Command
	$counter = 0
	foreach($arg in $Arguments) {
		$str = $str.Replace('{'+ $counter +'}',$arg)
		$counter++
	}	
	return [ScriptBlock]::Create($str)
}

function Fill-ScriptBlockWithArguments {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[ScriptBlock]$Command,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[array]$Arguments
	)
	LogMe
	
	$str = $Command.ToString()
	return Create-ScriptBlockWithArguments -Command $str -Arguments $Arguments
}

function Fill-TemplateWithArguments {
	[CmdletBinding()]     
	param (
		[Parameter(Mandatory=$True, ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		$Template,
		[Parameter(Mandatory=$true)]
		[HashTable]$Keywords
	)
	LogMe
	
	if($template.GetType().Name -eq "String" ){
	}
	elseif ($template.GetType().Name -eq "ScriptBlock") {
		$template = $template.ToString()
	}
	else {
		Write-Host "You can only pass [String] or [ScriptBlock] as a template!" -ForeGround Red
		return
	}	
	[regex]::Replace( 
		$template,
		'\{(?<tokenName>[\w\.]+)\}', 
		{
			param($match)
			$tokenName = $match.Groups['tokenName'].Value
			$tokenValue = $Keywords[$tokenName]
			if ($tokenValue) {
				return $tokenValue
			} 
			else {
				return $match
			}
		}
	)
} 

function Get-ADGroupsHasSIDHistory {
	[CmdletBinding()]
	param ()
	LogMe
	
	Import-ModuleIfNotYetImported ActiveDirectory
	
	[array]$groups = Get-ADGroup -Filter 'SIDHistory -like "*"' -Property Name, SID, SIDHistory | Select-Object * -ExpandProperty SIDHistory | Select-Object Name, SID, DistinguishedName, @{ Name = "SIDHistory"; Expression = { $_.Value } } | Group-Object -Property Name,SID,DistinguishedName | % { New-Object psobject @{Name = $_.Group.Name[0]; DistinguishedName = $_.Group.DistinguishedName[0]; SID = $_.Group.SID[0]; SIDHistory = $_.Group.SIDHistory} }

	$result = @()
	foreach ($group in $groups) {
		$sh = $group.SIDHistory
		foreach ($s in $sh) {
			$objSID = New-Object System.Security.Principal.SecurityIdentifier ($s)
			$objUser = $objSID.Translate([System.Security.Principal.NTAccount])
			$result += New-Object psobject @{Name = $group.Name; DistinguishedName = $group.DistinguishedName ; SID = $group.SID ; OldSID = $s ; OldPrincipalName =  $objUser.Value}
		}
	}
	return $result
}

function Get-ADUserGroupsSIDDetailed {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[ScriptBlock]$Account
	)
	LogMe
	
	$properties = @("SamAccountName", "GivenName", "Surname", "DisplayName", "DistinguishedName", "SID", "Memberof")
	$user = Get-ADUser -Identity $Account -Properties $properties
	$memberGroups = ($user | select Memberof).Memberof

	Write-Output ("User " + $user.SID.Translate([System.Security.Principal.NTAccount]) + " groups: ")
	
	$result = @()
	foreach ($memberGroup in $memberGroups) {
		$gDistinguishedName = $memberGroup | Out-String
		$gGroup = Get-ADGroup -Filter { DistinguishedName -eq $gDistinguishedName } -Properties SIDHistory | Select-Object * -ExpandProperty SIDHistory 
		$gName = $gGroup.Name
		$gSID = $gGroup.SID
		$SIDHistory = $gGroup | Select-Object DistinguishedName, @{ Name = "SIDHistory"; Expression = { $_.Value } }		
		if ($SIDHistory) {		
			$sh = $SIDHistory.sidhistory
			foreach ($s in $sh) {
				$objSID = New-Object System.Security.Principal.SecurityIdentifier ($s)
				$objUser = $objSID.Translate([System.Security.Principal.NTAccount])				
				$result += New-Object psobject @{GroupName = $gName; DistinguishedName = $gDistinguishedName; SID = $gSID ; OldSID = $s ; OldPrincipalName =  $objUser.Value}
			}
		}
		else {
			$result += New-Object psobject @{GroupName = $gName; DistinguishedName = $gDistinguishedName; SID = $gSID ; OldSID = "N/A" ; OldPrincipalName =  "N/A"}
		}
	}
	return $result
}

function Deploy-Certificates {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateScript(
			{
				Test-Path -Path $_
			}
		)]
		[string]$ConfigFile
	)
	LogMe
		
	[xml]$config = Get-Content $ConfigFile | Out-String | Expand-String
	
	$config.Configuration.Certificates.Certificate | % {	
		$file = $_.fileName
		$name = $_.Name
		$pwd  = $_.password
		$store = "cert:\LocalMachine\" + $_.store			
		if ($file.EndsWith(".crt")) {
			$crt = Import-Certificate -FilePath $file -CertStoreLocation $store -Confirm:$false
			Write-Output "Certificate $name is installed to $store :`r`n$crt"
		}
		elseif ($file.EndsWith(".pfx")) {
			$securePwd = ConvertTo-SecureString -String $pwd -Force -AsPlainText
			$pfx = Import-PfxCertificate -FilePath $file -CertStoreLocation $store -Exportable:$true -Password $securePwd -Confirm:$false
			Write-Output "Certificate $name is installed to $store :`r`n$pfx"
		}
	}
}

function Expand-String { 
	[CmdletBinding()]
	param( 
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)] 
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		[switch]$EnvironmentVariable 
	)
	LogMe

	if($EnvironmentVariable) { 
		[System.Environment]::ExpandEnvironmentVariables($Value) 
	} 
	else { 
		$ExecutionContext.InvokeCommand.ExpandString($Value) 
	} 
}

function Get-HostName {
	[CmdletBinding()]
	param( 
		[Parameter(Mandatory = $false, Position = 0)] 
		[switch]$FQDN 
	)
	LogMe
	if($FQDN) {
		return [System.Net.Dns]::GetHostByName(($env:ComputerName)).HostName.ToLower()
	}
	return ($env:ComputerName).ToLower()
}

#region Inline JIT Codes
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
namespace InProcess
{
    public class InMemoryJob : System.Management.Automation.Job
    {
        public InMemoryJob(ScriptBlock scriptBlock, string name)
        {
            _PowerShell = PowerShell.Create().AddScript(scriptBlock.ToString());
            SetUpStreams(name);
        }
        public InMemoryJob(PowerShell PowerShell, string name)
        {
            _PowerShell = PowerShell;
            SetUpStreams(name);
        }
        private void SetUpStreams(string name)
        {
            _PowerShell.Streams.Verbose = this.Verbose;
            _PowerShell.Streams.Error = this.Error;
            _PowerShell.Streams.Debug = this.Debug;
            _PowerShell.Streams.Warning = this.Warning;
            _PowerShell.Runspace.AvailabilityChanged +=
            new EventHandler<RunspaceAvailabilityEventArgs>(Runspace_AvailabilityChanged);
            int id = System.Threading.Interlocked.Add(ref InMemoryJobNumber, 1);
            if (!string.IsNullOrEmpty(name))
            {
                this.Name = name;
            }
            else
            {
                this.Name = "InProcessJob" + id;
            }
        }
        void Runspace_AvailabilityChanged(object sender, RunspaceAvailabilityEventArgs e)
        {
            if (e.RunspaceAvailability == RunspaceAvailability.Available)
            {
                this.SetJobState(JobState.Completed);
            }
        }
        PowerShell _PowerShell;
        static int InMemoryJobNumber = 0;
        public override bool HasMoreData
        {
            get
            {
                return (Output.Count > 0);
            }
        }
        public override string Location
        {
            get { return "In Process"; }
        }
        public override string StatusMessage
        {
            get { return "A new status message"; }
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (!isDisposed)
                {
                    isDisposed = true;
                    try
                    {
                        if (!IsFinishedState(JobStateInfo.State))
                        {
                            StopJob();
                        }
                        foreach (Job job in ChildJobs)
                        {
                            job.Dispose();
                        }
                    }
                    finally
                    {
                        base.Dispose(disposing);
                    }
                }
            }
        }
        private bool isDisposed = false;
        internal bool IsFinishedState(JobState state)
        {
            return (state == JobState.Completed || state == JobState.Failed || state ==
           JobState.Stopped);
        }
        public override void StopJob()
        {
            _PowerShell.Stop();
            _PowerShell.EndInvoke(_asyncResult);
            SetJobState(JobState.Stopped);
        }
        public void Start()
        {
            _asyncResult = _PowerShell.BeginInvoke<PSObject, PSObject>(null, Output);
            SetJobState(JobState.Running);
        }
        IAsyncResult _asyncResult;
        public void WaitJob()
        {
            _asyncResult.AsyncWaitHandle.WaitOne();
        }
        public void WaitJob(TimeSpan timeout)
        {
            _asyncResult.AsyncWaitHandle.WaitOne(timeout);
        }
    }
}
'@
#endregion

function Start-JobInProcess {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[ScriptBlock]$ScriptBlock,
		[Parameter(Mandatory = $false)]
		$ArgumentList,
		[Parameter(Mandatory = $false)]
		[string]$Name
	)
	LogMe
	
	function Get-JobRepository {
		[CmdletBinding()]
		param()
		
		$pscmdlet.JobRepository
	}
	function Add-Job {
		[CmdletBinding()]
		param($job)
		
		$pscmdlet.JobRepository.Add($job)
	}
	if ($ArgumentList) {
		$PowerShell = [PowerShell]::Create().AddScript($ScriptBlock).AddArgument($argumentlist)
		$MemoryJob = New-Object InProcess.InMemoryJob $PowerShell, $Name
	}
	else {
		$MemoryJob = New-Object InProcess.InMemoryJob $ScriptBlock, $Name
	}
	$MemoryJob.Start()
	Add-Job $MemoryJob
	$MemoryJob
}

function Test-ActiveDirectoryAccount {           
    [CmdletBinding()]
    [OutputType([String])]        
    Param ( 
        [Parameter( 
            Mandatory = $false, 
            ValueFromPipeLine = $true, 
            ValueFromPipelineByPropertyName = $true
        )] 
        [Alias('PSCredential')] 
        [ValidateNotNull()] 
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()] 
        $Credentials,
		[Parameter( 
            Mandatory = $false, 
            ValueFromPipeLine = $true, 
            ValueFromPipelineByPropertyName = $true
        )] 
		[string]
		$Username,
		[Parameter( 
            Mandatory = $false, 
            ValueFromPipeLine = $true, 
            ValueFromPipelineByPropertyName = $true
        )] 
		[string]
		$Password
    )
	LogMe
	
    $Domain = $null
    $Root = $null
    $Usr = $null
    $Pwd = $null
	
    if($Credentials -eq $null) {
		if(-not ($Password -eq $null -or $Password -eq "")) {
			$Pwd = ConvertTo-SecureString -AsPlainText -Force -String $Password
			$Usr = $Username
			$Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Usr, $Pwd
		}
		else {
			try {
				$Credentials = Get-Credential "$env:userdomain\$env:username" -ErrorAction Stop
			}
			catch {
				$ErrorMsg = $_.Exception.Message
				Write-Warning "Failed to validate credentials: $ErrorMsg "
				break
			}
		}
    }
	
    # Checking module
    try {
        # Split username and password
        $Usr = $credentials.username
        $Pwd = $credentials.GetNetworkCredential().password
  
        # Get Domain
        $Root = "LDAP://" + ([ADSI]'').distinguishedName
        $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$Usr,$Pwd)
    }
    catch {
        $_.Exception.Message
        continue
    }
  
    if(!$domain) {
        Write-Warning "Something went wrong"
    }
    else {
        if ($domain.name -ne $null) {
            return "Authenticated"
        }
        else {
            return "NotAuthenticated"
        }
    }
}

#region Function Exports
Export-ModuleMember -Function Get-Hotfixes
Export-ModuleMember -Function MakeAndChangeDirectory
Export-ModuleMember -Function Test-Alias
Export-ModuleMember -Function Get-EnvironmentValue
Export-ModuleMember -Function Convert-CmdVariable2PoShVariable
Export-ModuleMember -Function Add-PSSnapinIfNotYetAdded
Export-ModuleMember -Function Check-PSSnapinAvailable
Export-ModuleMember -Function Import-ModuleIfNotYetImported
Export-ModuleMember -Function Check-ModuleAvailable
Export-ModuleMember -Function Run-PSasAdmin
Export-ModuleMember -Function Run-CommandAsAdmin
Export-ModuleMember -Function Set-As
Export-ModuleMember -Function Create-Shortcut
Export-ModuleMember -Function Add-ScheduledTask
Export-ModuleMember -Function Delete-ScheduledTask
Export-ModuleMember -Function String-IsNullOrEmpty
Export-ModuleMember -Function Get-SystemService
Export-ModuleMember -Function Get-SystemServices
Export-ModuleMember -Function Get-DetailedInfoAboutScheduledTasks
Export-ModuleMember -Function Switch-ScheduledTaskState
Export-ModuleMember -Function Get-IISLogDirectories
Export-ModuleMember -Function Test-RegistryValue
Export-ModuleMember -Function Get-RegistryValue
Export-ModuleMember -Function Add-WebSites2Localhost
Export-ModuleMember -Function Zip
Export-ModuleMember -Function Unzip
Export-ModuleMember -Function Listen-Port
Export-ModuleMember -Function Test-IPPort
Export-ModuleMember -Function Get-WebSitesByURLorName
Export-ModuleMember -Function Test-AmIAdmin
Export-ModuleMember -Function Recycle-AppPoolsByURLorName
Export-ModuleMember -Function Get-OSVersion
Export-ModuleMember -Function Get-MyAllConsoleHistory
Export-ModuleMember -Function DoParallel-OnServers
Export-ModuleMember -Function ConvertTo-String
Export-ModuleMember -Function ConvertTo-PlainText
Export-ModuleMember -Function Get-HostProperties
Export-ModuleMember -Function New-LogEntry
Export-ModuleMember -Function CopyTo-AsParallel
Export-ModuleMember -Function Create-ScriptBlockWithArguments
Export-ModuleMember -Function Fill-ScriptBlockWithArguments
Export-ModuleMember -Function Fill-TemplateWithArguments
Export-ModuleMember -Function Get-ADGroupsHasSIDHistory
Export-ModuleMember -Function Get-ADUserGroupsSIDDetailed
Export-ModuleMember -Function Deploy-Certificates
Export-ModuleMember -Function Expand-String
Export-ModuleMember -Function Get-HostName
Export-ModuleMember -Function Start-JobInProcess
Export-ModuleMember -Function Test-ActiveDirectoryAccount
#endregion
