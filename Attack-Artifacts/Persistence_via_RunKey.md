; -------------------------------------------------------------------------
; ATTACK ARTIFACT: Registry Persistence (Run Key)
; PHASE: Persistence (T1547.001)
; -------------------------------------------------------------------------

; This file mimics a registry change used for persistence.
; It adds a key to automatically launch a script or executable when a user logs in.

Windows Registry Editor Version 5.00

; WARNING: Do not execute this file on a live machine.
; The path below is a placeholder and should reflect the actual script
; used in the lab, such as a C2 launcher or secondary payload.

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"ProjectX_Updater_Task"="C:\\Users\\Public\\Scripts\\updater.exe -silent"

; The Blue Team's custom Wazuh rules were designed to detect modification
; to this specific registry path, demonstrating successful Detection Engineering.
