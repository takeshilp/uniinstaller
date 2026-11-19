; Uniinstaller lab test app: one script for every EXE scenario, lab/build.ps1 passes /D defines.
; Inert payload (a copy of whoami.exe), nothing is started, no network. Never run the result on the host.
Unicode true
!ifndef NAME
  !error "NAME is required"
!endif
!ifndef KEY
  !error "KEY is required"
!endif
!ifndef EXE
  !error "EXE is required"
!endif
!ifndef OUT
  !error "OUT is required"
!endif
!ifndef PAYLOAD
  !error "PAYLOAD is required"
!endif
!ifndef VERSION
  !define VERSION "1.0"
!endif
!ifndef REGKEY
  !define REGKEY "SOFTWARE\Lab Vendor\${NAME}"
!endif
!define ARP "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${KEY}"
!define RUNKEY "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
!define APPPATHS "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\${EXE}"
!define SHAREDDLLS "SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"

Name "${NAME}"
OutFile "${OUT}"
SilentInstall silent
; shortcut: uninstallers are silent by design (no wizard to click), add a UI scenario if wizard uninstallers misbehave.
SilentUnInstall silent
!ifdef USER
  RequestExecutionLevel user
  InstallDir "$LOCALAPPDATA\Programs\${NAME}"
  !define HIVE HKCU
!else
  RequestExecutionLevel admin
  !ifdef DIR
    InstallDir "${DIR}"
  !else
    InstallDir "$PROGRAMFILES64\Lab Vendor\${NAME}"
  !endif
  !define HIVE HKLM
!endif

!macro Text path text
  FileOpen $9 "${path}" w
  FileWrite $9 "${text}"
  FileClose $9
!macroend

!macro Context
  SetRegView 64
  !ifndef USER
    SetShellVarContext all
  !endif
!macroend

Section
  !insertmacro Context
  SetOutPath "$INSTDIR"
  File "/oname=${EXE}" "${PAYLOAD}"
!ifndef NOARP
  ; NOARP: a portable-style drop with no uninstaller and no Uninstall entry (forced-removal scenarios).
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr ${HIVE} "${ARP}" "DisplayName" "${NAME}"
  WriteRegStr ${HIVE} "${ARP}" "DisplayVersion" "${VERSION}"
  WriteRegStr ${HIVE} "${ARP}" "Publisher" "Lab Vendor"
  WriteRegStr ${HIVE} "${ARP}" "InstallLocation" "$INSTDIR"
  WriteRegStr ${HIVE} "${ARP}" "DisplayIcon" "$INSTDIR\${EXE}"
  WriteRegStr ${HIVE} "${ARP}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD ${HIVE} "${ARP}" "NoModify" 1
  WriteRegDWORD ${HIVE} "${ARP}" "NoRepair" 1
!ifdef HIDDEN
  ; Hides the entry from Apps & Features, as runtime components and unwanted software do.
  WriteRegDWORD ${HIVE} "${ARP}" "SystemComponent" 1
!endif
!endif
  WriteRegStr ${HIVE} "${RUNKEY}" "${KEY}" '"$INSTDIR\${EXE}" /tray'
  WriteRegStr ${HIVE} "${APPPATHS}" "" "$INSTDIR\${EXE}"
  WriteRegStr ${HIVE} "${REGKEY}" "InstallDir" "$INSTDIR"
  CreateDirectory "$SMPROGRAMS\Lab Vendor"
  CreateShortCut "$SMPROGRAMS\Lab Vendor\${NAME}.lnk" "$INSTDIR\${EXE}"
  CreateShortCut "$DESKTOP\${NAME}.lnk" "$INSTDIR\${EXE}"
  SetShellVarContext current
  CreateDirectory "$APPDATA\Lab Vendor\${NAME}"
  !insertmacro Text "$APPDATA\Lab Vendor\${NAME}\settings.ini" "[lab]"
!ifdef DOCS
  CreateDirectory "$INSTDIR\My Work"
  !insertmacro Text "$INSTDIR\My Work\report.docx" "user document"
  CreateDirectory "$INSTDIR\Saves"
  !insertmacro Text "$INSTDIR\Saves\slot1.sav" "user save"
  CreateDirectory "$INSTDIR\logs"
  !insertmacro Text "$INSTDIR\logs\today.log" "log"
  !insertmacro Text "$INSTDIR\app.log" "log"
!endif
!ifdef JUNCTION
  CreateDirectory "C:\LabOutside"
  !insertmacro Text "C:\LabOutside\keep.txt" "outside the install dir, must survive"
  nsExec::Exec '"$SYSDIR\cmd.exe" /c mklink /J "$INSTDIR\link-out" "C:\LabOutside"'
  Pop $0
!endif
!ifdef LINKS
  CreateDirectory "$SMPROGRAMS\${NAME}"
  StrCpy $1 1
  lab_links:
    CreateShortCut "$SMPROGRAMS\${NAME}\Tool $1.lnk" "$INSTDIR\${EXE}"
    IntOp $1 $1 + 1
    IntCmp $1 12 lab_links lab_links
!endif
!ifdef SERVICE
  nsExec::Exec '"$SYSDIR\sc.exe" create LabSvcTool binPath= "\"$INSTDIR\${EXE}\"" start= demand'
  Pop $0
  nsExec::Exec '"$SYSDIR\schtasks.exe" /create /f /tn "Lab Vendor\${NAME} Update" /tr "\"$INSTDIR\${EXE}\"" /sc onlogon'
  Pop $0
  WriteRegStr HKLM "SOFTWARE\Classes\.labsvc" "" "LabSvcTool.File"
  WriteRegStr HKLM "SOFTWARE\Classes\LabSvcTool.File\shell\open\command" "" '"$INSTDIR\${EXE}" "%1"'
!endif
!ifdef SHARED_DLL
  SetOutPath "$COMMONFILES64\Lab Vendor"
  File "/oname=labshared.dll" "${PAYLOAD}"
  ReadRegDWORD $0 HKLM "${SHAREDDLLS}" "$COMMONFILES64\Lab Vendor\labshared.dll"
  IntOp $0 $0 + 1
  WriteRegDWORD HKLM "${SHAREDDLLS}" "$COMMONFILES64\Lab Vendor\labshared.dll" $0
  SetOutPath "$INSTDIR"
!endif
!ifdef EDITOR
  CreateDirectory "$APPDATA\Lab Vendor\Lab Editor"
  !insertmacro Text "$APPDATA\Lab Vendor\Lab Editor\settings-${KEY}.ini" "[${KEY}]"
  WriteRegStr HKCU "Software\Lab Vendor\Lab Editor" "${KEY}" "1"
!endif
!ifdef MODIFY
  ; Points values that exist before the install (scenario before_install) at this program: the trace records them as Modified.
  WriteRegStr HKCU "Software\Lab Shared" "Handler" "$INSTDIR\${EXE}"
  WriteRegStr HKLM "SOFTWARE\Lab Shared" "Handler" "$INSTDIR\${EXE}"
!endif
!ifdef BACKGROUND
  ; Stands in for a background writer during the trace (the trace cannot tell writers apart): unrelated to this program,
  ; so the product must neither preselect it nor offer a revert.
  SetOutPath "$PROGRAMFILES32\Other Updater"
  File "/oname=update.dat" "${PAYLOAD}"
  SetOutPath "$INSTDIR"
  SetRegView 32
  WriteRegStr HKLM "SOFTWARE\Other Vendor\Updater" "LastCheck" "2026-11-18"
  SetRegView 64
!endif
SectionEnd

!ifndef NOARP
Section "Uninstall"
  ; Deliberately incomplete like many real uninstallers: leaves the desktop shortcut, Run value, App Paths,
  ; vendor key, settings and every flag-specific object (service, task, association, documents, links).
  !insertmacro Context
  Delete "$INSTDIR\${EXE}"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\Lab Vendor\${NAME}.lnk"
  RMDir "$SMPROGRAMS\Lab Vendor"
!ifdef SHARED_DLL
  ReadRegDWORD $0 HKLM "${SHAREDDLLS}" "$COMMONFILES64\Lab Vendor\labshared.dll"
  IntOp $0 $0 - 1
  WriteRegDWORD HKLM "${SHAREDDLLS}" "$COMMONFILES64\Lab Vendor\labshared.dll" $0
!endif
  DeleteRegKey ${HIVE} "${ARP}"
  RMDir "$INSTDIR"
SectionEnd
!endif
