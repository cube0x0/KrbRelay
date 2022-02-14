using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace CheckPort
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[*] Looking for available ports..");
            string port = checkPorts(new string[] { "SYSTEM", "ANY" }).ToString();
            if (port == "-1")
            {
                Console.WriteLine("[-] No available ports found");
                Console.WriteLine("[-] Firewall will block our COM connection. Exiting");
                return;
            }
        }
        public static int checkPorts(string[] names)
        {
            IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] tcpConnInfoArray = ipGlobalProperties.GetActiveTcpListeners();
            List<int> tcpPorts = tcpConnInfoArray.Select(i => i.Port).ToList();

            foreach (string name in names)
            {
                for (int i = 10; i < 65535; i++)
                {
                    if (checkPort(i, name) && !tcpPorts.Contains(i))
                    {
                        Console.WriteLine("[*] {0} Is allowed through port {1}", name, i);
                        return i;
                    }
                }
            }
            return -1;
        }
        public static bool checkPort(int port, string name = "SYSTEM")
        {
            INetFwMgr mgr = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            if (!mgr.LocalPolicy.CurrentProfile.FirewallEnabled)
            {
                return true;
            }
            mgr.IsPortAllowed(name, NET_FW_IP_VERSION_.NET_FW_IP_VERSION_ANY, port, "", NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP, out object allowed, out object restricted);
            return (bool)allowed;
        }
    }
}
