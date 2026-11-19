// Test and lab lock holder (never shipped): a window program without a console. Arguments: the file to hold with no sharing ("-" holds
// nothing: a bystander), a file to write "ok" into once it holds, and the seconds after which it closes its own window.
// Restart Manager reports it as a main-window program. Keep this file ASCII-only.
using System;
using System.IO;
using System.Windows.Forms;

public static class LockHolder
{
    [STAThread]
    public static void Main(string[] args)
    {
        FileStream held = args[0] == "-" ? null : File.Open(args[0], FileMode.Open, FileAccess.Read, FileShare.None);
        File.WriteAllText(args[1], "ok");
        Form w = new Form();
        w.Text = "uniinstaller lock holder";
        w.ShowInTaskbar = true;
        w.WindowState = FormWindowState.Minimized;
        Timer t = new Timer();
        t.Interval = int.Parse(args[2]) * 1000;
        t.Tick += delegate { w.Close(); };
        t.Start();
        Application.Run(w);
        if (held != null) held.Close();
    }
}
