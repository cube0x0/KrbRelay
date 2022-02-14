using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace KrbRelay.Spoofing
{
    class UDP
    {
        public static UdpClient UDPListener(string type, string listenerIP, int listenerPort, string ipVersion)
        {
            AddressFamily listenerAddressFamily = AddressFamily.InterNetwork;

            if (String.Equals(ipVersion, "IPv6"))
            {
                listenerAddressFamily = AddressFamily.InterNetworkV6;
            }

            IPEndPoint sourceEndpoint = new IPEndPoint(IPAddress.Parse(listenerIP), listenerPort);
            UdpClient udpClient = new UdpClient(listenerAddressFamily);

            try
            {
                udpClient.ExclusiveAddressUse = false;
                udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                udpClient.Client.Bind(sourceEndpoint);

                if (String.Equals(type, "LLMNR"))
                {
                    udpClient.JoinMulticastGroup(IPAddress.Parse("224.0.0.252"));
                }
                else if (String.Equals(type, "MDNS"))
                {
                    udpClient.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"));
                }
                else if (String.Equals(type, "DHCPv6"))
                {
                    udpClient.JoinMulticastGroup(IPAddress.Parse("ff02::1:2"));
                }

            }
            catch
            {
                Console.WriteLine(String.Format("[-] Error starting unprivileged DNS spoofer, UDP port sharing does not work on all versions of Windows.", DateTime.Now.ToString("s")));
                throw;
            }

            return udpClient;
        }

        public static void UDPListenerClient(IPAddress destinationIP, int destinationPort, UdpClient udpClient, byte[] udpResponse)
        {
            IPEndPoint destinationEndpoint = new IPEndPoint(destinationIP, destinationPort);
            udpClient.Connect(destinationEndpoint);
            udpClient.Send(udpResponse, udpResponse.Length);
            udpClient.Close();
        }

        public static void UDPSnifferClient(IPAddress sourceIP, int sourcePort, IPAddress destinationIP, int destinationPort, string ipVersion, byte[] udpResponse)
        {
            AddressFamily ipVersionAddressFamily = AddressFamily.InterNetwork;
            IPEndPoint sourceEndpoint;

            if (String.Equals(ipVersion, "IPv6"))
            {
                ipVersionAddressFamily = AddressFamily.InterNetworkV6;
            }

            Socket udpSendSocket = new Socket(ipVersionAddressFamily, SocketType.Raw, ProtocolType.Udp);
            udpSendSocket.SendBufferSize = 1024;

            if (sourceIP != null)
            {
                sourceEndpoint = new IPEndPoint(sourceIP, sourcePort);
                udpSendSocket.Bind(sourceEndpoint);
            }

            IPEndPoint destinationEndpoint = new IPEndPoint(destinationIP, destinationPort);
            udpSendSocket.SendTo(udpResponse, destinationEndpoint);
            udpSendSocket.Close();
        }

    }
}
