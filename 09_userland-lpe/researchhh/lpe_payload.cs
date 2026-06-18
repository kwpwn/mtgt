using System;
using System.IO;
using System.Security.Principal;
class LpePayload {
    static void Main() {
        string out_ = @"C:\Users\Public\lpe_proof.txt";
        var id = WindowsIdentity.GetCurrent();
        var p = new WindowsPrincipal(id);
        string il = "UNKNOWN";
        foreach (var g in id.Groups) {
            if (g.Value == "S-1-16-12288") il = "HIGH";
            else if (g.Value == "S-1-16-8192") il = "MEDIUM";
        }
        File.WriteAllText(out_,
            "IL=" + il + "\n" +
            "IsAdmin=" + p.IsInRole(WindowsBuiltInRole.Administrator) + "\n" +
            "User=" + id.Name + "\n");
    }
}
