clear-host
#------SSP dll injection----
([string[]](Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'Security Packages')."Security Packages").Where({$_ -notin "kerberos","msv1_0","schannel","wdigest","tspkg","pku2u"}) | % -Begin { write-host "`n`t**********  Rouge security support provider dll  **********`n" }{ write-host "dll: $_ "} -End { write-host "are listed as an SSP`n-------------------------------------`n"}


#-----possible privilege scalation, password change disabled -----
if ([int](Get-itemProperty -Path HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters -Name 'DisablePasswordChange').DisablePasswordChange -eq 1 ) { write-host "**********  Machine Account password change disabled  **********`n`nHKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters\DisabledPasswordChange is enabled"} else {write-host "**********  Machine Account password change enabled  as usual**********`n`n-------------------------------------`n"}


#------Image File Options Debbuging back-door
"Utilman.exe","sethc.exe","osk.exe","Narrator.exe","Magnify.exe" | % -Begin {write-host "`n **********  Ease-of-access Center Backdoor  **********`n Image File Execution options provides you with a mechanism to always launch an executable directly under the debugger`nunder registry-key:HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`n`n"}  {
        if ([string](Get-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'+$_) -Name Debugger -ErrorAction Ignore).Debugger -imatch ".*(powershell|cmd).*"){
            write-host "$_ Debbuger Option INFECTED in registry: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_"
        } else {
                    write-host "$_ Debbuger Option not infected"
        }
    
} -End { write-host "`n-------------------------------------`n"}


#------Script-code in debug keys --------------
"HKLM:\SOFTWARE\Microsoft\Network","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" | % -Begin { write-host "`n ********** Possible script code *********`n`n" } {
    $scriptcode=(Get-ItemProperty -Path $_  -name Debug -ErrorAction Ignore).Debug
    if ( $scriptcode -ne $null){
        write-host "`n ...key: $_ INFECTED!"
        [string]$scriptcodeDecoded=[System.IO.StreamReader]::new( [System.IO.MemoryStream]::new([byte[]][System.Convert]::FromBase64String($scriptcode)) ).ReadToEnd().Replace(";",";`n").Replace("\x00","")
        write-host $scriptcodeDecoded

    } else {
        write-host "not script in: $_\Debug"
    }
} -End { write-host "`n-------------------------------------`n" }

#-----Initial scripts session -----------------------
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | % -Begin { write-host "`n ********** Initial Scripts run startup *********`n`n" } {
    $hashi=@{}; $hashi=Get-ItemProperty -Path $_
     @((Get-Member -InputObject $hashi -MemberType NoteProperty ).Name).Where({$_ -inotmatch "^PS.*"}) | % { 
                            if ($hashi.$_ -imatch ".*(powershell|cmd).*") {
                                write-host "nombre:$_ .... valor:" $hashi.$_ " INFECTED BY OBSCURE-SHELL`n"
                                } else {
                                write-host "nombre: $_ ... valor:" $hashi.$_ " ... SECURE"
                                }                          
                            
                            } 
} -End { write-host "`n-------------------------------------`n" }


#--------- taskscheduling with bad-scripts ---------
Get-ScheduledTask | % -Begin {write-host "`n********** Found Evil Scheduled Task **********`n`n"} { if ($_.Actions[0].Execute -imatch ".*\\\s*(powershell|cmd)\.exe.*"){ write-host "Tarea sospechosa:" $_.Path " nombre:" $_.TaskName "....accion:_" $_.Actions[0].Execute " " $_.Actions[0].Arguments } } -End { write-host "`n-------------------------------------`n" }

#---------- scripts launch with system-events: wmi eventsubscriber ----------------
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | ? { $_.__CLASS -ieq "activescripteventconsumer"} | % -Begin {write-host "`n********** Found Evil WMI subscription **********`n`n"} { 
                write-host "script malicioso hecho en:" $_.ScriptingEngine
                if ($_.ScriptFileName -ne ""){ 
                        write-host "localizado en: " $_.ScriptFileName " ... contenido:`n"
                        Get-Content -Path $_.ScriptFileName 
                        } else {
                                write-host "contenido del script:`n" $_.ScriptText
                        }
                   }
