# Lab helper: answers Yes in msiexec dialog boxes while uni-lab runs the native uninstaller. Keep this file ASCII-only.
# Posts WM_COMMAND(IDYES) to the dialog itself: works whether or not the dialog is active, never depends on button text.
# shortcut: only IDYES in #32770 dialogs of msiexec, add other ids when a scenario needs them.
param([Parameter(Mandatory)][string]$Log)
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class LabClicker {
    delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
    const uint WM_COMMAND = 0x0111;
    const int IDYES = 6;
    public static List<string> AnswerYes(uint[] pids) {
        var lines = new List<string>();
        EnumWindows((h, l) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (!IsWindowVisible(h) || Array.IndexOf(pids, pid) < 0) return true;
            var cls = new StringBuilder(64); GetClassName(h, cls, 64);
            var title = new StringBuilder(256); GetWindowText(h, title, 256);
            IntPtr yes = cls.ToString() == "#32770" ? GetDlgItem(h, IDYES) : IntPtr.Zero;
            if (yes != IntPtr.Zero && PostMessage(h, WM_COMMAND, (IntPtr)IDYES, yes)) lines.Add("posted Yes to '" + title + "' hwnd " + h);
            else lines.Add("seen '" + title + "' (" + cls + ")");
            return true;
        }, IntPtr.Zero);
        return lines;
    }
}
'@
$logged = @{}
while ($true) {
    $pids = [uint32[]]@(Get-Process msiexec -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
    if ($pids.Count -gt 0) {
        foreach ($line in [LabClicker]::AnswerYes($pids)) {
            if (-not $logged.ContainsKey($line)) { $logged[$line] = 1; Add-Content $Log "$(Get-Date -Format o) $line" }
        }
    }
    Start-Sleep -Milliseconds 500
}
