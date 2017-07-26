#Test
Function Add-SyncthingDevice
    {
        <#
        .SYNOPSIS
        Adds a new device to Syncthing.
 
        .DESCRIPTION
        This command adds a new device to Syncthing.
 
        .EXAMPLE
        Add-SyncthingDevice -Computer 192.168.1.100 -Port 8080 -DeviceID "XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX" -Name "Device01"
 
        .EXAMPLE
        Add-SyncthingDevice -DeviceID "XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX"
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384

        .PARAMETER DeviceID
        The Device ID of the device you want to add

        .PARAMETER Name
        The name you want to assign to the device. If not given, the device name broadcasted by the device will be used.

        #>
        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384",
            [Parameter(Mandatory=$true)][String]$DeviceID,
            [String]$Name
            )

        if($Config -eq $null)
            {
                $Config = Get-SyncthingConfig -Computer $Computer -Port $Port
            }

        $Device = New-Object -TypeName psobject
        $Device | Add-Member -MemberType NoteProperty -Name deviceID -Value $DeviceID
        $Device | Add-Member -MemberType NoteProperty -Name name -Value $Name

        $Config.devices += $Device
        Set-SyncthingConfig -Computer $Computer -Port $Port -Config $Config
    }

Function Add-SyncthingFolder
    {
        <#
        .SYNOPSIS
        Adds a given folder to the Syncthing Config.
 
        .DESCRIPTION
        This command adds a given folder to the config object supplied by Get-SyncthingConfig or existing config object.
 
        .EXAMPLE
        Add-SyncthingFolder -Computer 192.168.1.100 -Port 8080 -FolderId "Folder1" -Path "C:\Folder1"
 
        .EXAMPLE
        Add-SyncthingFolder -Path "C:\Folder1"
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384

        .PARAMETER FolderId
        The FolderId of the Folder. If not given, the folder name will be used. Each word in the folder name will be capitalised and whitespaces will be replaced with underscores. For example, the folder "important stuff" will get the folder ID "Important_Stuff".
        
        .PARAMETER Path
        The full Path of the folder.

        #>

        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384", 
            [String]$FolderId,
            [Parameter(Mandatory=$true)][String]$Path
            )

        if(!($FolderId))
            {
                $FolderId = Split-Path -Leaf $Path
                $FolderId = (Get-Culture).textinfo.totitlecase($FolderId.tolower())
                $FolderId = $FolderId.Replace(" ","_")
                Write-Verbose "FolderID will be $FolderId"
            }

        if(!($Config))
            {
                $Config = Get-SyncthingConfig -Computer $Computer -Port $Port
            }
        
        $Folder = New-Object -TypeName psobject
        $Folder | Add-Member -MemberType NoteProperty -Name rescanIntervalS -Value 60
        $Folder | Add-Member -MemberType NoteProperty -Name order -Value "random"
        $Folder | Add-Member -MemberType NoteProperty -Name fileVersionSelector -Value "none"
        $Folder | Add-Member -MemberType NoteProperty -Name trashcanClean -Value 0
        $Folder | Add-Member -MemberType NoteProperty -Name simpleKeep -Value 5
        $Folder | Add-Member -MemberType NoteProperty -Name staggeredMaxAge -Value 365
        $Folder | Add-Member -MemberType NoteProperty -Name staggeredCleanInterval -Value 3600
        $Folder | Add-Member -MemberType NoteProperty -Name staggeredVersionsPath -Value ""
        $Folder | Add-Member -MemberType NoteProperty -Name externalCommand -Value ""
        $Folder | Add-Member -MemberType NoteProperty -Name autoNormalize -Value $true
        $Folder | Add-Member -MemberType NoteProperty -Name id -Value $FolderId
        $Folder | Add-Member -MemberType NoteProperty -Name path -Value $Path

        Write-Verbose "Adding folder to config"
        $Config.folders += $Folder
        Set-SyncthingConfig -Computer $Computer -Port $Port -Config $Config
    }

Function Get-SyncthingAPIkey
    {
        <#
        .SYNOPSIS
        Gets the API key of Syncthing.
 
        .DESCRIPTION
        This command gets the API key of Syncthing.
 
        .EXAMPLE
        Get-SyncthingAPIkey -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingAPIkey
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>

        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"   
            )

        $Config = Get-SyncthingConfig -Computer $Computer -Port $Port
        $ApiKey = $Config.gui.apikey
        Write-Verbose "APIkey is $ApiKey"
        return $ApiKey
    }

Function Get-SyncthingConfig    
    {
        <#
        .SYNOPSIS
        Gets the current Syncthing Config.
 
        .DESCRIPTION
        This command gets the current config of Syncthing.
 
        .EXAMPLE
        Get-SyncthingConfig -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingConfig
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>

        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"   
            )

        $Url = "http://$Computer"+":"+"$Port/rest/system/config"
        Write-Verbose "Getting config from $url"
        $Config = Invoke-RestMethod -Uri $Url -Method Get
        return $Config
    }

Function Get-SyncthingDeviceID
    {
        <#
        .SYNOPSIS
        Gets the device ID of Syncthing.
 
        .DESCRIPTION
        This command gets the device ID of Syncthing.
 
        .EXAMPLE
        Get-SyncthingDeviceID -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingDeviceID
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>
        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"   
            )

        $Config = Get-SyncthingStatus -Computer $Computer -Port $Port
        $MyDeviceID = $Config.myID
        return $MyDeviceID
    }

Function Get-SyncthingDevices
    {
        <#
        .SYNOPSIS
        Gets the devices of Syncthing.
 
        .DESCRIPTION
        This command gets all the devices of Syncthing.
 
        .EXAMPLE
        Get-SyncthingDevices -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingDevices
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>
        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"   
            )

        $Config = Get-SyncthingConfig -Computer $Computer -Port $Port
        $Devices = $Config.devices
        return $Devices
    }

Function Get-SyncthingFilesRemaining
    {
        <#
        .SYNOPSIS
        Gets the remaining files of a Syncthing folder.
 
        .DESCRIPTION
        This command gets the remaining files of a given Syncthing Folder.
 
        .EXAMPLE
        Get-SyncthingFolders -Computer 192.168.1.100 -Port 8080 -FolderID Private_Folder
 
        .EXAMPLE
        Get-SyncthingFolders -FolderID Private_Folder
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384

        .PARAMETER FolderID
        The FolderID of the folder you wish to get a list of remaining files
        
        #>
        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384",
            [Parameter(Mandatory=$true)][String]$FolderID 
            )
        $ApiKey = Get-SyncthingAPIkey
        $BaseUrl = "http://$Computer"+":"+"$Port/rest/db/need"
        $Url = $BaseUrl+"?folder=$FolderID"
        $Files = Invoke-RestMethod -Uri $Url -Method Get -Headers @{"X-API-Key" = $ApiKey}
        return $Files
    }

Function Get-SyncthingFolders
    {
        <#
        .SYNOPSIS
        Gets the folders of Syncthing.
 
        .DESCRIPTION
        This command gets all the folders of Syncthing.
 
        .EXAMPLE
        Get-SyncthingFolders -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingFolders
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>
        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"   
            )

        $Config = Get-SyncthingConfig -Computer $Computer -Port $Port
        $Folders = $Config.folders
        return $Folders
    }

Function Get-SyncthingStatus
    {
        <#
        .SYNOPSIS
        Gets the current Syncthing status.
 
        .DESCRIPTION
        This command gets the current status of Syncthing.
 
        .EXAMPLE
        Get-SyncthingStatus -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingStatus
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>

        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"   
            )

        $Url = "http://$Computer"+":"+"$Port/rest/system/status"
        $Status = Invoke-RestMethod -Uri $Url -Method Get
        return $Status
    }

Function Get-SyncthingSyncStatus
    {
        <#
        .SYNOPSIS
        Gets the Syncthing Sync Status.
 
        .DESCRIPTION
        This command gets the sync status of all folders. Takes a lot of CPU, use sparingly.
 
        .EXAMPLE
        Get-SyncthingSyncStatus -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingSyncStatus
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>
        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"
            )
       
            $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
            $SyncStatusArray = @()

            foreach ($FolderID in ((Get-SyncthingFolders -Computer $Computer -Port $Port).id))
                {
                    $BaseUrl = "http://$Computer"+":"+"$Port/rest/db/status"
                    $Url = $BaseUrl+"?folder=$FolderID"
                    $Completion = Invoke-RestMethod -Uri $Url -Method Get -Headers @{"X-API-Key" = $ApiKey}
                    $MegaBytesRemaining = [math]::Round($Completion.needBytes/1000000)

                    $Files = Get-SyncthingFilesRemaining -Computer $Computer -Port $Port -FolderID $FolderID

                    $SyncStatus = New-Object -TypeName psobject
                    $SyncStatus | Add-Member -MemberType NoteProperty -Name FolderID -Value $FolderID
                    $SyncStatus | Add-Member -MemberType NoteProperty -Name MegaBytesRemaining -Value $MegaBytesRemaining
                    $SyncStatus | Add-Member -MemberType NoteProperty -Name FilesRemaining -Value $Completion.needFiles
                    $SyncStatus | Add-Member -MemberType NoteProperty -Name QueuedFiles -Value $Files.queued.name
                    $SyncStatus | Add-Member -MemberType NoteProperty -Name RestFiles -Value $Files.rest.name
                    $SyncStatusArray += $SyncStatus
                }
            return $SyncStatusArray
    }

Function Get-SyncthingVersion    
    {
        <#
        .SYNOPSIS
        Gets the current Syncthing version.
 
        .DESCRIPTION
        This command gets the current version of Syncthing.
 
        .EXAMPLE
        Get-SyncthingVersion -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Get-SyncthingConfig
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>

        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"   
            )

        $Url = "http://$Computer"+":"+"$Port/rest/system/upgrade"
        $Version = Invoke-RestMethod -Uri $Url -Method Get
        return $Version
    }

Function Install-Syncthing
    {
        <#
        .SYNOPSIS
        Installs Syncthing.
 
        .DESCRIPTION
        This Command downloads and installs the latest stable version of Syncthing.
 
        .EXAMPLE
        Install-Syncthing -Path "C:\Program Files(x86)" -RunAtStartup $true
 
        .EXAMPLE
        Install-Syncthing
 
        .PARAMETER Path
        The path where Syncthing will get installed. Default is "C:".

        .PARAMETER RunAtStartup
        Whether or not Syncthing shall start automatically. Default is $false
        
        #>

        [CmdletBinding()]
        Param
            (
            [String]$Path="C:\",
            [ValidateSet($true,$false)][string]$RunAtStartup=$false  
            )
        if(!(Test-Path $Path))
            {
                Write-Verbose "Creating $Path"
                New-Item -ItemType Directory -Path $Path -Force
            }
        Write-Verbose "Getting latest release"
        $htmlsyncthing = Invoke-WebRequest "https://github.com/syncthing/syncthing/releases" -DisableKeepAlive
        $syncthingzipurl = "https://github.com" + ($htmlsyncthing.Links.href | Where-Object {$_ -like "*windows-amd64*"} | select -First 1)
        Write-Verbose "Downloading Syncthing"
        Invoke-WebRequest $syncthingzipurl -OutFile $env:TEMP\Syncthing.zip -DisableKeepAlive
        Write-Verbose "Installing Syncthing"
        Expand-Archive $env:TEMP\Syncthing.zip $Path -Force
        Get-ChildItem $Path | Where-Object {$_.Name -like "*syncthing*"} | Rename-Item -NewName "Syncthing"

        if($RunAtStartup -eq $true)
            {
                '"'+"$Path\Syncthing\syncthing.exe"+'"'+ ' -no-console -no-browser' | Out-File "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\syncthing.cmd"
            }

        Write-Verbose Syncthing is installed. The exe is located in $Path"\Syncthing"
    }

Function Restart-Syncthing
    {
        <#
        .SYNOPSIS
        Restarts Syncthing.
 
        .DESCRIPTION
        This command restarts Syncthing.
 
        .EXAMPLE
        Restart-Syncthing -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Restart-Syncthing
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>
        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"   
            )

        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $Url = "http://$Computer"+":"+"$Port/rest/system/restart"
        Invoke-RestMethod -Uri $Url -Method Post -Headers @{"X-API-Key" = $ApiKey} | Out-Null
        Write-Verbose "Syncthing is restarting"
    }

Function Set-SyncthingConfig
    {
        <#
        .SYNOPSIS
        Sets the Syncthing Config.
 
        .DESCRIPTION
        This command sets the config of Syncthing. It converts the psobject to json and posts it to Syncthing. Gets applied only after syncthing restarts. Use Restart-Syncthing or the webui to do so.
 
        .EXAMPLE
        Set-SyncthingConfig -Computer 192.168.1.100 -Port 8080 -Config $Config
 
        .EXAMPLE
        Set-SyncthingConfig -Config $Config
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384

        .PARAMETER Config
        The config object, originally from Get-SyncthingConfig
        
        #>
        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384",
                    $Config
            )

        $Url = "http://$Computer"+":"+"$Port/rest/system/config"
        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $ConfigJson = $Config | ConvertTo-Json -Compress -Depth 6
        Write-Verbose "Posting Config to $Url"
        Invoke-RestMethod -Uri $Url -Method Post -Body $ConfigJson -Headers @{"X-API-Key" = $ApiKey} -ContentType application/json
    }

Function Stop-Syncthing
    {
        <#
        .SYNOPSIS
        Shuts down syncthing.
 
        .DESCRIPTION
        This command shuts down Syncthing.
 
        .EXAMPLE
        Shutdown-Syncthing -Computer 192.168.1.100 -Port 8080
 
        .EXAMPLE
        Shutdown-Syncthing
 
        .PARAMETER Computer
        The IP or hostname of the computer that runs Syncthing. Default value is localhost.
 
        .PARAMETER Port
        The tcp port of Syncthing. Default value is 8384
        
        #>
        [CmdletBinding()]
        Param
            (
            [String]$Computer="localhost",
            [String]$Port="8384"   
            )

        $ApiKey = Get-SyncthingAPIkey -Computer $Computer -Port $Port
        $Url = "http://$Computer"+":"+"$Port/rest/system/shutdown"
        Invoke-RestMethod -Uri $Url -Method Post -Headers @{"X-API-Key" = $ApiKey} | Out-Null
        Write-Verbose "Syncthing has shut down"
    }
