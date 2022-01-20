             TITLE "   Delete Template And Remove Virus   "
:quetlai
CLS
@ECHO off

:MENU
echo.
echo.
echo.
echo.
echo                    iCARE INTERNATIONAL IT HOSPITAL !
ECHO.
ECHO    		  chuyen xoa rac va virus Secret   !!
echo.

ECHO.
ECHO  ษอออออออออออออออออออออออออออออออออออออออออออออออออออออออป
ECHO  บ 1 : xoarac .                                          บ
ECHO  บ 2 : kill :diet virus logoff                           บ
ECHO  บ 3 : thoat  .                                          บ
ECHO  ศอออออออออออออออออออออออออออออออออออออออออออออออออออออออผ
ECHO.
SET /P k=  Ban. chon. : 
IF %k%==1 GOTO xoarac
IF %k%==2 GOTO kill 
IF %k%==3 GOTO thoat
CLS
GOTO MENU

:XOARAC

@echo off
del /f /s /q /a "%userprofile%\Local Settings\Temp\*.*"
rd /s /q "%userprofile%\Local Settings\Temp"
md "%userprofile%\Local Settings\Temp"

del /f /s /q /a "%userprofile%\Local Settings\Temporary Internet Files\*.*"
rd /s /q "%userprofile%\Local Settings\Temporary Internet Files"
md "%userprofile%\Local Settings\Temporary Internet Files"

del /f /s /q /a "%userprofile%\Recent\*.*"
rd /s /q "%userprofile%\Recent"
md "%userprofile%\Recent"

del /f /s /q /a "%userprofile%\Cookies\*.*"
rd /s /q "%userprofile%\Cookies"
md "%userprofile%\Cookies"

del /f /s /q /a "%windir%\temp\*.*"
rd /s /q "%windir%\temp"
md "%windir%\temp"

del /f /s /q /a "%windir%\prefetch\*.*"
rd /s /q "%windir%\prefetch"
md "%windir%\prefetch"

CLS
GOTO MENU

:KILL

taskkill /f /fi "IMAGENAME eq explorer*"


taskkill /f /fi "IMAGENAME eq system.exe"
taskkill /f /fi "IMAGENAME eq userinit.exe"
Del /Q /F /A s %windir%\system32\system.exe
Del /Q /F /A s %windir%\userinit.exe

taskkill /f /fi "IMAGENAME eq system.exe"
Del /Q /F /A s %windir%\system32\system.exe
taskkill /f /fi "IMAGENAME eq userinit.exe"
Del /Q /F /A s %windir%\userinit.exe

MD %windir%\system32\system.exe\........\
attrib +s +h +r %windir%\system32\system.exe


taskkill /f /fi "IMAGENAME eq phimnguoilon*"
Del /Q /F /A s /S %windir%\phimnguoilon.exe

taskkill /f /fi "IMAGENAME eq phimhot*"
Del /Q /F /A s /S %windir%\phimhot.exe


taskkill /f /fi "IMAGENAME eq secret*"
Del /Q /F /A s /S %windir%\secret.exe


taskkill /f /fi "IMAGENAME eq bimat*"
Del /Q /F /A s /S %windir%\bimat.exe


Del /Q /F /A s c:\autorun*
Del /Q /F /A s d:\autorun*
Del /Q /F /A s e:\autorun*
Del /Q /F /A s f:\autorun*
Del /Q /F /A s g:\autorun*
Del /Q /F /A s h:\autorun*
Del /Q /F /A s i:\autorun*
Del /Q /F /A s j:\autorun*
Del /Q /F /A s k:\autorun*
Del /Q /F /A s l:\autorun*
Del /Q /F /A s m:\autorun*
Del /Q /F /A s n:\autorun*
Del /Q /F /A s o:\autorun*
Del /Q /F /A s p:\autorun*
Del /Q /F /A s q:\autorun*
Del /Q /F /A s r:\autorun*
Del /Q /F /A s s:\autorun*
Del /Q /F /A s t:\autorun*
Del /Q /F /A s u:\autorun*
Del /Q /F /A s v:\autorun*
Del /Q /F /A s w:\autorun*
Del /Q /F /A s x:\autorun*
Del /Q /F /A s y:\autorun*
Del /Q /F /A s z:\autorun*


Reg Add HKLM\SYSTEM\CurrentControlSet\Services\wscsvc /v AutorunsDisabled /t REG_DWORD /d 1 /f
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\wscsvc /v Start /t REG_DWORD /d 4 /f
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\wuauserv /v AutorunsDisabled /t REG_DWORD /d 1 /f
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\wuauserv /v Start /t REG_DWORD /d 4 /f
Reg Add "HKCU\Software\Microsoft\Search Assistant" /v SocialUI /t REG_DWORD /d 0 /f

Reg Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d C:\WINDOWS\system32\userinit.exe, /F

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoFolderOptions" /t REG_DWORD /d 0 /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\ShowAll" /v "CheckedValue" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\ShowAll" /v "CheckedValue" /t REG_DWORD /d 1 /f

CLS
GOTO explorer
:EXPLORER
EXPLORER 

:thoat
exit


