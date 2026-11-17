@echo off
rem Windows Sandbox LogonCommand. run.ps1 checks the token user first, does the work and shuts the guest down.
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\lab\guest\run.ps1 > C:\out\guest.log 2>&1
