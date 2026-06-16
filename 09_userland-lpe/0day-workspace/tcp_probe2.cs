using System;
using System.Net.Sockets;
using System.Text;
using System.Threading;

class TcpProbe2 {
    static void Probe(int port, byte[][] sends) {
        Console.WriteLine("=== Port {0} ===", port);
        try {
            var tcp = new TcpClient();
            tcp.Connect("127.0.0.1", port);
            tcp.ReceiveTimeout = 2000;
            tcp.SendTimeout = 3000;
            var s = tcp.GetStream();
            var buf = new byte[4096];
            s.ReadTimeout = 1500;
            try {
                int n = s.Read(buf, 0, buf.Length);
                if (n > 0) {
                    Console.Write("  [INIT] HEX: ");
                    for (int i = 0; i < Math.Min(n, 64); i++) Console.Write("{0:X2} ", buf[i]);
                    Console.WriteLine();
                    Console.WriteLine("  [INIT] TXT: " + Encoding.UTF8.GetString(buf, 0, Math.Min(n, 128)));
                } else Console.WriteLine("  [INIT] 0 bytes");
            } catch { Console.WriteLine("  [INIT] timeout/closed"); }
            foreach (var send in sends) {
                s.Write(send, 0, send.Length); s.Flush();
                System.Threading.Thread.Sleep(500);
                try {
                    int n = s.Read(buf, 0, buf.Length);
                    if (n > 0) {
                        Console.Write("  [RESP] HEX: ");
                        for (int i = 0; i < Math.Min(n, 64); i++) Console.Write("{0:X2} ", buf[i]);
                        Console.WriteLine();
                        Console.WriteLine("  [RESP] TXT: " + Encoding.UTF8.GetString(buf, 0, Math.Min(n, 128)));
                    } else Console.WriteLine("  [RESP] 0 bytes");
                } catch { Console.WriteLine("  [RESP] timeout"); break; }
            }
            tcp.Close();
        } catch (Exception e) { Console.WriteLine("  ERR: " + e.Message); }
    }
    static void Main() {
        Probe(22112, new byte[][] { new byte[]{0,0,0,0}, Encoding.UTF8.GetBytes("GET / HTTP/1.0\r\n\r\n"), Encoding.UTF8.GetBytes("{\"cmd\":\"hello\"}") });
        Probe(51100, new byte[][] { new byte[]{0,0,0,0}, Encoding.UTF8.GetBytes("GET / HTTP/1.0\r\n\r\n"), Encoding.UTF8.GetBytes("{\"cmd\":\"hello\"}") });
        Probe(13031, new byte[][] { Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") });
        Probe(50100, new byte[][] { new byte[]{0,0,0,0,0,0,0,0}, Encoding.UTF8.GetBytes("{\"type\":\"ping\"}") });
    }
}
