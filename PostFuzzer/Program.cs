using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Net;

namespace PostFuzzer
{
    class Program
    {
        static void Main(string[] args)
        {
            string[] requestLines = File.ReadAllLines(args[0]);
            string[] parms = requestLines[requestLines.Length - 1].Split('&');
            string host = string.Empty;
            StringBuilder requestBuilder = new StringBuilder();

            foreach (string ln in requestLines)
            {
                if (ln.StartsWith("Host:"))
                    host = ln.Split(' ')[1].Replace("\r", string.Empty);
                requestBuilder.Append(ln + "\n");
            }
            string request = requestBuilder.ToString() + "\r\n";
            Console.WriteLine(request);
            IPEndPoint rhost = new IPEndPoint(IPAddress.Parse(host), 80);
            foreach (string parm in parms)
            {
                using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    sock.Connect(rhost);

                    string val = parm.Split('=')[1];
                    string req = request.Replace("=" + val, "=" + val + "=" + val + "'");

                    byte[] reqBytes = Encoding.ASCII.GetBytes(req);
                    sock.Send(reqBytes);

                    byte[] buf = new byte[sock.ReceiveBufferSize];

                    sock.Receive(buf);
                    string response = Encoding.ASCII.GetString(buf);

                    if (response.Contains("error in your SQL syntax"))
                    {
                        Console.WriteLine("Parameter " + parm + " seems vulnerable to SQL injection with value: " + val + "'");
                      
                    }
                }
            }

        }
    }
}
