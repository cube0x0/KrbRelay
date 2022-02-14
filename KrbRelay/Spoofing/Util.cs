using System;
using System.Linq;
using System.Text;
using System.Net;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.IO;

namespace KrbRelay.Spoofing
{
    class Util
    {
        public static string GetLocalIPAddress(string ipVersion)
        {

            List<string> ipAddressList = new List<string>();
            AddressFamily addressFamily;

            if (String.Equals(ipVersion, "IPv4"))
            {
                addressFamily = AddressFamily.InterNetwork;
            }
            else
            {
                addressFamily = AddressFamily.InterNetworkV6;
            }

            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {

                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet && networkInterface.OperationalStatus == OperationalStatus.Up)
                {

                    foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                    {

                        if (ip.Address.AddressFamily == addressFamily)
                        {
                            ipAddressList.Add(ip.Address.ToString());
                        }

                    }

                }

            }

            return ipAddressList.FirstOrDefault();
        }

        public static byte[] IntToByteArray2(int field)
        {
            byte[] byteArray = BitConverter.GetBytes(field);
            Array.Reverse(byteArray);
            return byteArray.Skip(2).ToArray();
        }

        public static string CheckRequest(string nameRequest, string sourceIP, string mainIP, string type, string requestType, string[] recordTypes)
        {
            string responseMessage = "response sent";
            bool isRepeat = false;
            bool domainIgnoreMatch = false;
            bool domainReplyMatch = false;
            string[] nameRequestSplit;
            string nameRequestHost = "";
            string domainIgnore = "";

            if (nameRequest.Contains("."))
            {
                nameRequestSplit = nameRequest.Split('.');
                nameRequestHost = nameRequestSplit[0];
            }
            else
            {
                nameRequestHost = nameRequest;
            }

            //Console.WriteLine(String.Format("CheckRequest"));
            //Console.WriteLine(String.Format("[{0}] ", nameRequestHost));


            //if (!Program.enabledSpooferRepeat)
            //{
            //
            //    if (String.Equals(type, "DNS"))
            //    {
            //        string sourceIPCheck = sourceIP.Split('%')[0];
            //        string mappedIP = "";
            //        string host = "";
            //
            //        if (!Program.enabledSpooferRepeat)
            //        {
            //
            //            foreach (string hostMapping in Program.hostList)
            //            {
            //                string[] hostArray = hostMapping.Split(',');
            //
            //                if (!String.IsNullOrEmpty(hostArray[1]) && String.Equals(hostArray[1].Split('%')[0], sourceIPCheck.Split('%')[0]))
            //                {
            //                    host = hostArray[0].Split('.')[0].ToUpper();
            //                }
            //                else if (!String.IsNullOrEmpty(hostArray[2]) && String.Equals(hostArray[2], sourceIPCheck))
            //                {
            //                    host = hostArray[0].Split('.')[0].ToUpper();
            //                }
            //
            //            }
            //
            //            if (!String.IsNullOrEmpty(host))
            //            {
            //
            //                foreach (string capture in Program.ntlmv2UsernameList)
            //                {
            //
            //                    if (!String.IsNullOrEmpty(capture.Split(',')[1]) && capture.Split(',')[1].StartsWith(host))
            //                    {
            //                        mappedIP = capture.Split(',')[0];
            //                    }
            //
            //                }
            //
            //                if (String.IsNullOrEmpty(mappedIP))
            //                {
            //
            //                    foreach (string capture in Program.ntlmv1UsernameList)
            //                    {
            //
            //                        if (!String.IsNullOrEmpty(capture.Split(',')[1]) && capture.Split(',')[1].StartsWith(host))
            //                        {
            //                            mappedIP = capture.Split(',')[0];
            //                        }
            //
            //                    }
            //
            //                }
            //
            //                if (!String.IsNullOrEmpty(mappedIP))
            //                {
            //
            //                    foreach (string capture in Program.ntlmv2UsernameList)
            //                    {
            //
            //                        if (capture.StartsWith(mappedIP) && !capture.EndsWith("$"))
            //                        {
            //                            isRepeat = true;
            //                        }
            //
            //                    }
            //
            //                    foreach (string capture in Program.ntlmv1UsernameList)
            //                    {
            //
            //                        if (capture.StartsWith(mappedIP) && !capture.EndsWith("$"))
            //                        {
            //                            isRepeat = true;
            //                        }
            //
            //                    }
            //
            //                }
            //
            //            }
            //
            //        }
            //
            //    }
            //
            //}
            //
            //if (String.Equals(type, "DNS") && nameRequest.Contains(".") && Program.argSpooferDomainsIgnore != null)
            //{
            //
            //    foreach (string domain in Program.argSpooferDomainsIgnore)
            //    {
            //
            //        if (!domainIgnoreMatch && nameRequest.ToUpper().EndsWith(String.Concat(".", domain)))
            //        {
            //            domainIgnoreMatch = true;
            //            domainIgnore = domain;
            //        }
            //
            //    }
            //
            //}
            //
            //if (String.Equals(type, "DNS") && nameRequest.Contains(".") && Program.argSpooferDomainsReply != null)
            //{
            //
            //    foreach (string domain in Program.argSpooferDomainsReply)
            //    {
            //
            //        if (!domainReplyMatch && nameRequest.ToUpper().EndsWith(String.Concat(".", domain)))
            //        {
            //            domainReplyMatch = true;
            //        }
            //
            //    }
            //
            //}
            //
            //if (Program.enabledInspect)
            //{
            //    responseMessage = "inspect only";
            //}
            //else if ((String.Equals(type, "LLMNR") && !Program.enabledLLMNR) || (String.Equals(type, "LLMNRv6") && !Program.enabledLLMNRv6) || (String.Equals(type, "NBNS") && !Program.enabledNBNS) ||
            //    (String.Equals(type, "MDNS") && !Program.enabledMDNS) || (String.Equals(type, "DNS") && !Program.enabledDNS && !String.Equals(sourceIP, mainIP)))
            //{
            //    responseMessage = "spoofer disabled";
            //}
            //else if (recordTypes != null && recordTypes.Length > 0 && (!Array.Exists(recordTypes, element => element == requestType.ToUpper())))
            //{
            //    responseMessage = String.Concat(requestType, " replies disabled");
            //}
            //else if (Program.argSpooferHostsIgnore != null && Program.argSpooferHostsIgnore.Length > 0 && (Array.Exists(Program.argSpooferHostsIgnore, element => element == nameRequest.ToUpper()) ||
            //    (Array.Exists(Program.argSpooferHostsIgnore, element => element == nameRequestHost.ToUpper()))))
            //{
            //    responseMessage = String.Concat(nameRequest, " is on ignore list");
            //}
            //else if (Program.argSpooferHostsReply != null && Program.argSpooferHostsReply.Length > 0 && (!Array.Exists(Program.argSpooferHostsReply, element => element == nameRequest.ToUpper()) &&
            //    (!Array.Exists(Program.argSpooferHostsReply, element => element == nameRequestHost.ToUpper()))))
            //{
            //    responseMessage = String.Concat(nameRequest, " not on reply list");
            //}
            //else if (Program.argSpooferIPsIgnore != null && Array.Exists(Program.argSpooferIPsIgnore, element => element == sourceIP))
            //{
            //    responseMessage = String.Concat(sourceIP, " is on ignore list");
            //}
            //else if (Program.argSpooferIPsReply != null && !Array.Exists(Program.argSpooferIPsReply, element => element == sourceIP))
            //{
            //    responseMessage = String.Concat(sourceIP, " not on reply list");
            //}
            //else if (String.Equals(type, "NBNS") && String.Equals(sourceIP, mainIP))
            //{
            //    responseMessage = "local query";
            //}
            //else if (String.Equals(type, "DNS") && domainIgnoreMatch)
            //{
            //    responseMessage = String.Concat(domainIgnore, " is on ignore list");
            //}
            //else if (String.Equals(type, "DNS") && Program.argSpooferDomainsReply != null && !domainReplyMatch)
            //{
            //    responseMessage = "domain not on reply list";
            //}
            //else if (isRepeat)
            //{
            //    responseMessage = String.Concat("previous ", sourceIP, " capture");
            //}

            return responseMessage;
        }

        public static UInt16 GetPacketChecksum(byte[] pseudoHeader, byte[] payload)
        {
            int e = 0;

            if ((pseudoHeader.Length + payload.Length) % 2 != 0)
            {
                e = 1;
            }

            byte[] packet = new byte[pseudoHeader.Length + payload.Length + e];
            Buffer.BlockCopy(pseudoHeader, 0, packet, 0, pseudoHeader.Length);
            Buffer.BlockCopy(payload, 0, packet, pseudoHeader.Length, payload.Length);
            UInt32 packetChecksum = 0;
            int length = packet.Length;
            int index = 0;

            while (index < length)
            {
                packetChecksum += Convert.ToUInt32(BitConverter.ToUInt16(packet, index));
                index += 2;
            }

            packetChecksum = (packetChecksum >> 16) + (packetChecksum & 0xffff);
            packetChecksum += (packetChecksum >> 16);

            return (UInt16)(~packetChecksum);
        }

        public static Byte[] GetIPv6PseudoHeader(IPAddress sourceIP, IPAddress destinationIP, int nextHeader, int length)
        {
            byte[] lengthData = BitConverter.GetBytes(length);
            Array.Reverse(lengthData);
            byte[] pseudoHeader = new byte[40];
            Buffer.BlockCopy(sourceIP.GetAddressBytes(), 0, pseudoHeader, 0, 16);
            Buffer.BlockCopy(destinationIP.GetAddressBytes(), 0, pseudoHeader, 16, 16);
            Buffer.BlockCopy(lengthData, 0, pseudoHeader, 32, 4);
            pseudoHeader[39] = (byte)nextHeader;

            return pseudoHeader;
        }

        public static string ParseNameQuery(int index, byte[] nameQuery)
        {
            string hostname = "";
            byte[] queryLength = new byte[1];
            System.Buffer.BlockCopy(nameQuery, index, queryLength, 0, 1);
            int hostnameLength = queryLength[0];
            int i = 0;

            do
            {
                int hostnameSegmentLength = hostnameLength;
                byte[] hostnameSegment = new byte[hostnameSegmentLength];
                System.Buffer.BlockCopy(nameQuery, (index + 1), hostnameSegment, 0, hostnameSegmentLength);
                hostname += Encoding.UTF8.GetString(hostnameSegment);
                index += hostnameLength + 1;
                hostnameLength = nameQuery[index];
                i++;

                if (hostnameLength > 0)
                {
                    hostname += ".";
                }

            }
            while (hostnameLength != 0 && i <= 127);

            return hostname;
        }

    }

}
