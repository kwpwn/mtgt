/*
 * ws_probe.cs — WebSocket probe for ArmourySocketServer port 9013
 * Build: csc /nologo ws_probe.cs /out:ws_probe.exe
 * Run:   ws_probe.exe
 */
using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

class WsProbe {
    static TcpClient tcp;
    static NetworkStream stream;

    static byte[] MakeFrame(string text) {
        var payload = Encoding.UTF8.GetBytes(text);
        var mask = new byte[4];
        new Random().NextBytes(mask);
        var frame = new System.Collections.Generic.List<byte>();
        frame.Add(0x81); // FIN + text opcode
        int len = payload.Length;
        if (len < 126) {
            frame.Add((byte)(0x80 | len)); // MASK bit + length
        } else if (len < 65536) {
            frame.Add(0x80 | 126);
            frame.Add((byte)(len >> 8));
            frame.Add((byte)(len & 0xFF));
        } else {
            frame.Add(0x80 | 127);
            for (int i = 7; i >= 0; i--) frame.Add((byte)((len >> (i*8)) & 0xFF));
        }
        frame.AddRange(mask);
        for (int i = 0; i < payload.Length; i++)
            frame.Add((byte)(payload[i] ^ mask[i % 4]));
        return frame.ToArray();
    }

    static string ReadFrame(int timeoutMs = 3000) {
        try {
            stream.ReadTimeout = timeoutMs;
            var header = new byte[2];
            int r = stream.Read(header, 0, 2);
            if (r < 2) return null;
            bool fin = (header[0] & 0x80) != 0;
            int opcode = header[0] & 0x0F;
            bool masked = (header[1] & 0x80) != 0;
            int payLen = header[1] & 0x7F;
            if (payLen == 126) {
                var ext = new byte[2]; stream.Read(ext, 0, 2);
                payLen = (ext[0] << 8) | ext[1];
            } else if (payLen == 127) {
                var ext = new byte[8]; stream.Read(ext, 0, 8);
                payLen = (int)(((long)ext[0]<<56)|((long)ext[1]<<48)|((long)ext[2]<<40)|((long)ext[3]<<32)|
                               ((long)ext[4]<<24)|((long)ext[5]<<16)|((long)ext[6]<<8)|ext[7]);
            }
            if (opcode == 8) return "<CLOSE>";
            if (opcode == 9) { /* pong */ var pb = new byte[payLen]; stream.Read(pb,0,payLen); return "<PING>"; }
            var payload = new byte[payLen];
            int got = 0;
            while (got < payLen) { int n = stream.Read(payload, got, payLen - got); if (n <= 0) break; got += n; }
            return Encoding.UTF8.GetString(payload);
        } catch { return null; }
    }

    static void SendCmd(string json) {
        Console.WriteLine("[SEND] " + json);
        var frame = MakeFrame(json);
        stream.Write(frame, 0, frame.Length);
        stream.Flush();
        Thread.Sleep(300);
        string resp = ReadFrame(2000);
        Console.WriteLine("[RECV] " + (resp ?? "<null>"));
        // Try reading more frames
        string extra;
        while ((extra = ReadFrame(500)) != null)
            Console.WriteLine("[MORE] " + extra);
    }

    static void Main(string[] args) {
        tcp = new TcpClient("127.0.0.1", 9013);
        stream = tcp.GetStream();
        stream.WriteTimeout = 5000;

        // Handshake
        string key = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        string req = "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:9013\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                     "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
        var reqBytes = Encoding.ASCII.GetBytes(req);
        stream.Write(reqBytes, 0, reqBytes.Length);
        stream.Flush();

        // Read HTTP 101 response
        stream.ReadTimeout = 3000;
        var sb = new StringBuilder();
        var buf = new byte[4096];
        int n = stream.Read(buf, 0, buf.Length);
        string handshakeResp = Encoding.ASCII.GetString(buf, 0, n);
        if (!handshakeResp.Contains("101")) {
            Console.WriteLine("Handshake failed: " + handshakeResp);
            return;
        }
        Console.WriteLine("[+] WebSocket connected on port 9013");
        Console.WriteLine("[+] Server: " + handshakeResp.Split('\n')[2].Trim());

        // Send initial message (server may expect something first)
        Thread.Sleep(200);
        string firstMsg = ReadFrame(1000);
        if (firstMsg != null) Console.WriteLine("[INITIAL] " + firstMsg);

        // Try various commands
        var commands = new[] {
            "{\"command\":\"GetProductName\"}",
            "{\"command\":\"GetDeviceProfileList\"}",
            "{\"command\":\"GetMacroList\"}",
            "{\"command\":\"GetDeviceLightingControl\"}",
            "{\"command\":\"ScenarioProfileList\"}",
            "{\"command\":\"MacroNew\",\"fileName\":\"lpe_test\",\"fileData\":\"test\"}",
            "{\"command\":\"LaunchAuraCreator\"}",
            "{\"command\":\"Launch P303LocalUpdate.exe\"}",
            "{\"command\":\"MacroNew\",\"filepath\":\"C:\\\\ProgramData\\\\test\"}",
            "{\"command\":\"SetDeviceProfile\",\"filepath\":\"C:\\\\ProgramData\\\\lpe_test.dll\"}",
        };

        foreach (var cmd in commands) {
            SendCmd(cmd);
        }

        tcp.Close();
        Console.WriteLine("[+] Done");
    }
}
