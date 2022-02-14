/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.NetBios;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace SMBLibrary.Server
{
    /// <summary>
    /// NetBIOS name service server
    /// </summary>
    public class NameServer
    {
        public static readonly int NetBiosNameServicePort = 137;
        public static readonly string WorkgroupName = "WORKGROUP";

        private IPAddress m_serverAddress;
        private IPAddress m_broadcastAddress;
        private UdpClient m_client;
        private bool m_listening;

        public NameServer(IPAddress serverAddress, IPAddress subnetMask)
        {
            if (serverAddress.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("NetBIOS name service can only supply IPv4 addresses");
            }

            if (IPAddress.Equals(serverAddress, IPAddress.Any))
            {
                // When registering a NetBIOS name, we must supply the client with a usable IPAddress.
                throw new ArgumentException("NetBIOS name service requires an IPAddress that is associated with a specific network interface");
            }

            m_serverAddress = serverAddress;
            m_broadcastAddress = GetBroadcastAddress(serverAddress, subnetMask);
        }

        public void Start()
        {
            if (!m_listening)
            {
                m_listening = true;

                m_client = new UdpClient(new IPEndPoint(m_serverAddress, NetBiosNameServicePort));
                m_client.BeginReceive(ReceiveCallback, null);

                ThreadStart threadStart = new ThreadStart(RegisterNetBIOSName);
                Thread thread = new Thread(threadStart);
                thread.Start();
            }
        }

        public void Stop()
        {
            m_listening = false;
            m_client.Close();
        }

        private void ReceiveCallback(IAsyncResult result)
        {
            if (!m_listening)
            {
                return;
            }

            IPEndPoint remoteEP = null;
            byte[] buffer;
            try
            {
                buffer = m_client.EndReceive(result, ref remoteEP);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                return;
            }

            // Process buffer
            if (buffer.Length > NameServicePacketHeader.Length)
            {
                NameServicePacketHeader header = new NameServicePacketHeader(buffer, 0);
                if (header.OpCode == NameServiceOperation.QueryRequest)
                {
                    NameQueryRequest request = null;
                    try
                    {
                        request = new NameQueryRequest(buffer, 0);
                    }
                    catch
                    {
                    }
                    if (request != null)
                    {
                        if (request.Question.Type == NameRecordType.NB)
                        {
                            string name = NetBiosUtils.GetNameFromMSNetBiosName(request.Question.Name);
                            NetBiosSuffix suffix = (NetBiosSuffix)request.Question.Name[15];

                            bool nameMatch = String.Equals(name, Environment.MachineName, StringComparison.OrdinalIgnoreCase);

                            if (nameMatch && ((suffix == NetBiosSuffix.WorkstationService) || (suffix == NetBiosSuffix.FileServiceService)))
                            {
                                PositiveNameQueryResponse response = new PositiveNameQueryResponse();
                                response.Header.TransactionID = request.Header.TransactionID;
                                response.Resource.Name = request.Question.Name;
                                NameFlags nameFlags = new NameFlags();
                                response.Addresses.Add(m_serverAddress.GetAddressBytes(), nameFlags);
                                byte[] responseBytes = response.GetBytes();
                                m_client.Send(responseBytes, responseBytes.Length, remoteEP);
                            }
                        }
                        else // NBStat
                        {
                            NodeStatusResponse response = new NodeStatusResponse();
                            response.Header.TransactionID = request.Header.TransactionID;
                            response.Resource.Name = request.Question.Name;
                            NameFlags nameFlags = new NameFlags();
                            string name1 = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
                            string name2 = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.FileServiceService);
                            NameFlags nameFlags3 = new NameFlags();
                            nameFlags3.WorkGroup = true;
                            string name3 = NetBiosUtils.GetMSNetBiosName(WorkgroupName, NetBiosSuffix.WorkstationService);
                            response.Names.Add(name1, nameFlags);
                            response.Names.Add(name2, nameFlags);
                            response.Names.Add(name3, nameFlags3);
                            byte[] responseBytes = response.GetBytes();
                            try
                            {
                                m_client.Send(responseBytes, responseBytes.Length, remoteEP);
                            }
                            catch (ObjectDisposedException)
                            {
                            }
                        }
                    }
                }
            }

            try
            {
                m_client.BeginReceive(ReceiveCallback, null);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (SocketException)
            {
            }
        }

        private void RegisterNetBIOSName()
        {
            NameRegistrationRequest request1 = new NameRegistrationRequest(Environment.MachineName, NetBiosSuffix.WorkstationService, m_serverAddress);
            NameRegistrationRequest request2 = new NameRegistrationRequest(Environment.MachineName, NetBiosSuffix.FileServiceService, m_serverAddress);
            NameRegistrationRequest request3 = new NameRegistrationRequest(WorkgroupName, NetBiosSuffix.WorkstationService, m_serverAddress);
            request3.NameFlags.WorkGroup = true;
            RegisterName(request1);
            RegisterName(request2);
            RegisterName(request3);
        }

        private void RegisterName(NameRegistrationRequest request)
        {
            byte[] packet = request.GetBytes();

            IPEndPoint broadcastEP = new IPEndPoint(m_broadcastAddress, NetBiosNameServicePort);
            for (int index = 0; index < 4; index++)
            {
                try
                {
                    m_client.Send(packet, packet.Length, broadcastEP);
                }
                catch (ObjectDisposedException)
                {
                }

                if (index < 3)
                {
                    System.Threading.Thread.Sleep(250);
                }
            }
        }

        public static IPAddress GetBroadcastAddress(IPAddress address, IPAddress subnetMask)
        {
            byte[] ipAdressBytes = address.GetAddressBytes();
            byte[] subnetMaskBytes = subnetMask.GetAddressBytes();

            byte[] broadcastAddress = new byte[ipAdressBytes.Length];
            for (int i = 0; i < broadcastAddress.Length; i++)
            {
                broadcastAddress[i] = (byte)(ipAdressBytes[i] | (subnetMaskBytes[i] ^ 255));
            }
            return new IPAddress(broadcastAddress);
        }
    }
}