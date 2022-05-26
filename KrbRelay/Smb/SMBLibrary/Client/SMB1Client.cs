/* Copyright (C) 2014-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using SMBLibrary.Authentication.NTLM;
using SMBLibrary.NetBios;
using SMBLibrary.Services;
using SMBLibrary.SMB1;
using Utilities;

namespace SMBLibrary.Client
{
    public class SMB1Client : ISMBClient
    {
        private const string NTLanManagerDialect = "NT LM 0.12";
        
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;

        private static readonly ushort ClientMaxBufferSize = 65535; // Valid range: 512 - 65535
        private static readonly ushort ClientMaxMpxCount = 1;
        private static readonly int ResponseTimeoutInMilliseconds = 5000;

        private SMBTransportType m_transport;
        private bool m_isConnected;
        private bool m_isLoggedIn;
        private Socket m_clientSocket;
        private bool m_forceExtendedSecurity;
        private bool m_unicode;
        private bool m_largeFiles;
        private bool m_infoLevelPassthrough;
        private bool m_largeRead;
        private bool m_largeWrite;
        private uint m_serverMaxBufferSize;
        private ushort m_maxMpxCount;

        private object m_incomingQueueLock = new object();
        private List<SMB1Message> m_incomingQueue = new List<SMB1Message>();
        private EventWaitHandle m_incomingQueueEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private SessionPacket m_sessionResponsePacket;
        private EventWaitHandle m_sessionResponseEventHandle = new EventWaitHandle(false, EventResetMode.AutoReset);

        private ushort m_userID;
        private byte[] m_serverChallenge;
        private byte[] m_securityBlob;
        private byte[] m_sessionKey;

        public SMB1Client()
        {
        }

        public bool Connect(string serverName, SMBTransportType transport)
        {
            IPHostEntry hostEntry = Dns.GetHostEntry(serverName);
            if (hostEntry.AddressList.Length == 0)
            {
                throw new Exception(String.Format("Cannot resolve host name {0} to an IP address", serverName));
            }
            IPAddress serverAddress = hostEntry.AddressList[0];
            return Connect(serverAddress, transport);
        }

        public bool Connect(IPAddress serverAddress, SMBTransportType transport)
        {
            return Connect(serverAddress, transport, true);
        }

        public bool Connect(IPAddress serverAddress, SMBTransportType transport, bool forceExtendedSecurity)
        {
            int port = (transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort);
            return Connect(serverAddress, transport, port, forceExtendedSecurity);
        }

        private bool Connect(IPAddress serverAddress, SMBTransportType transport, int port, bool forceExtendedSecurity)
        {
            m_transport = transport;
            if (!m_isConnected)
            {
                m_forceExtendedSecurity = forceExtendedSecurity;
                if (!ConnectSocket(serverAddress, port))
                {
                    return false;
                }
                
                if (transport == SMBTransportType.NetBiosOverTCP)
                {
                    SessionRequestPacket sessionRequest = new SessionRequestPacket();
                    sessionRequest.CalledName = NetBiosUtils.GetMSNetBiosName("*SMBSERVER", NetBiosSuffix.FileServiceService);
                    sessionRequest.CallingName = NetBiosUtils.GetMSNetBiosName(Environment.MachineName, NetBiosSuffix.WorkstationService);
                    TrySendPacket(m_clientSocket, sessionRequest);

                    SessionPacket sessionResponsePacket = WaitForSessionResponsePacket();
                    if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                    {
                        m_clientSocket.Disconnect(false);
                        if (!ConnectSocket(serverAddress, port))
                        {
                            return false;
                        }

                        NameServiceClient nameServiceClient = new NameServiceClient(serverAddress);
                        string serverName = nameServiceClient.GetServerName();
                        if (serverName == null)
                        {
                            return false;
                        }

                        sessionRequest.CalledName = serverName;
                        TrySendPacket(m_clientSocket, sessionRequest);

                        sessionResponsePacket = WaitForSessionResponsePacket();
                        if (!(sessionResponsePacket is PositiveSessionResponsePacket))
                        {
                            return false;
                        }
                    }
                }

                bool supportsDialect = NegotiateDialect(m_forceExtendedSecurity);
                if (!supportsDialect)
                {
                    m_clientSocket.Close();
                }
                else
                {
                    m_isConnected = true;
                }
            }
            return m_isConnected;
        }

        private bool ConnectSocket(IPAddress serverAddress, int port)
        {
            m_clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            
            try
            {
                m_clientSocket.Connect(serverAddress, port);
            }
            catch (SocketException)
            {
                return false;
            }

            ConnectionState state = new ConnectionState(m_clientSocket);
            NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
            m_clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), state);
            return true;
        }

        public void Disconnect()
        {
            if (m_isConnected)
            {
                m_clientSocket.Disconnect(false);
                m_isConnected = false;
            }
        }

        private bool NegotiateDialect(bool forceExtendedSecurity)
        {
            NegotiateRequest request = new NegotiateRequest();
            request.Dialects.Add(NTLanManagerDialect);

            TrySendMessage(request);
            SMB1Message reply = WaitForMessage(CommandName.SMB_COM_NEGOTIATE);
            if (reply == null)
            {
                return false;
            }

            if (reply.Commands[0] is NegotiateResponse && !forceExtendedSecurity)
            {
                NegotiateResponse response = (NegotiateResponse)reply.Commands[0];
                m_unicode = ((response.Capabilities & Capabilities.Unicode) > 0);
                m_largeFiles = ((response.Capabilities & Capabilities.LargeFiles) > 0);
                bool ntSMB = ((response.Capabilities & Capabilities.NTSMB) > 0);
                bool rpc = ((response.Capabilities & Capabilities.RpcRemoteApi) > 0);
                bool ntStatusCode = ((response.Capabilities & Capabilities.NTStatusCode) > 0);
                m_infoLevelPassthrough = ((response.Capabilities & Capabilities.InfoLevelPassthrough) > 0);
                m_largeRead = ((response.Capabilities & Capabilities.LargeRead) > 0);
                m_largeWrite = ((response.Capabilities & Capabilities.LargeWrite) > 0);
                m_serverMaxBufferSize = response.MaxBufferSize;
                m_maxMpxCount = Math.Min(response.MaxMpxCount, ClientMaxMpxCount);
                m_serverChallenge = response.Challenge;
                return ntSMB && rpc && ntStatusCode;
            }
            else if (reply.Commands[0] is NegotiateResponseExtended)
            {
                NegotiateResponseExtended response = (NegotiateResponseExtended)reply.Commands[0];
                m_unicode = ((response.Capabilities & Capabilities.Unicode) > 0);
                m_largeFiles = ((response.Capabilities & Capabilities.LargeFiles) > 0);
                bool ntSMB = ((response.Capabilities & Capabilities.NTSMB) > 0);
                bool rpc = ((response.Capabilities & Capabilities.RpcRemoteApi) > 0);
                bool ntStatusCode = ((response.Capabilities & Capabilities.NTStatusCode) > 0);
                m_infoLevelPassthrough = ((response.Capabilities & Capabilities.InfoLevelPassthrough) > 0);
                m_largeRead = ((response.Capabilities & Capabilities.LargeRead) > 0);
                m_largeWrite = ((response.Capabilities & Capabilities.LargeWrite) > 0);
                m_serverMaxBufferSize = response.MaxBufferSize;
                m_maxMpxCount = Math.Min(response.MaxMpxCount, ClientMaxMpxCount);
                m_securityBlob = response.SecurityBlob;
                return ntSMB && rpc && ntStatusCode;
            }
            else
            {
                return false;
            }
        }

        public NTStatus Login(string domainName, string userName, string password)
        {
            return Login(domainName, userName, password, AuthenticationMethod.NTLMv2);
        }

        public byte[] Login(byte[] ticket, out bool success)
        {
            throw new NotImplementedException();
        }

        public NTStatus Login(string domainName, string userName, string password, AuthenticationMethod authenticationMethod)
        {
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A connection must be successfully established before attempting login");
            }

            Capabilities clientCapabilities = Capabilities.NTSMB | Capabilities.RpcRemoteApi | Capabilities.NTStatusCode | Capabilities.NTFind;
            if (m_unicode)
            {
                clientCapabilities |= Capabilities.Unicode;
            }
            if (m_largeFiles)
            {
                clientCapabilities |= Capabilities.LargeFiles;
            }
            if (m_largeRead)
            {
                clientCapabilities |= Capabilities.LargeRead;
            }

            if (m_serverChallenge != null)
            {
                SessionSetupAndXRequest request = new SessionSetupAndXRequest();
                request.MaxBufferSize = ClientMaxBufferSize;
                request.MaxMpxCount = m_maxMpxCount;
                request.Capabilities = clientCapabilities;
                request.AccountName = userName;
                request.PrimaryDomain = domainName;
                byte[] clientChallenge = new byte[8];
                new Random().NextBytes(clientChallenge);
                if (authenticationMethod == AuthenticationMethod.NTLMv1)
                {
                    request.OEMPassword = NTLMCryptography.ComputeLMv1Response(m_serverChallenge, password);
                    request.UnicodePassword = NTLMCryptography.ComputeNTLMv1Response(m_serverChallenge, password);
                }
                else if (authenticationMethod == AuthenticationMethod.NTLMv1ExtendedSessionSecurity)
                {
                    // [MS-CIFS] CIFS does not support Extended Session Security because there is no mechanism in CIFS to negotiate Extended Session Security
                    throw new ArgumentException("SMB Extended Security must be negotiated in order for NTLMv1 Extended Session Security to be used");
                }
                else // NTLMv2
                {
                    // Note: NTLMv2 over non-extended security session setup is not supported under Windows Vista and later which will return STATUS_INVALID_PARAMETER.
                    // https://msdn.microsoft.com/en-us/library/ee441701.aspx
                    // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                    request.OEMPassword = NTLMCryptography.ComputeLMv2Response(m_serverChallenge, clientChallenge, password, userName, domainName);
                    NTLMv2ClientChallenge clientChallengeStructure = new NTLMv2ClientChallenge(DateTime.UtcNow, clientChallenge, AVPairUtils.GetAVPairSequence(domainName, Environment.MachineName));
                    byte[] temp = clientChallengeStructure.GetBytesPadded();
                    byte[] proofStr = NTLMCryptography.ComputeNTLMv2Proof(m_serverChallenge, temp, password, userName, domainName);
                    request.UnicodePassword = ByteUtils.Concatenate(proofStr, temp);
                }
                
                TrySendMessage(request);

                SMB1Message reply = WaitForMessage(CommandName.SMB_COM_SESSION_SETUP_ANDX);
                if (reply != null)
                {
                    m_isLoggedIn = (reply.Header.Status == NTStatus.STATUS_SUCCESS);
                    return reply.Header.Status;
                }
                return NTStatus.STATUS_INVALID_SMB;
            }
            else // m_securityBlob != null
            {
                byte[] negotiateMessage = NTLMAuthenticationHelper.GetNegotiateMessage(m_securityBlob, domainName, authenticationMethod);
                if (negotiateMessage == null)
                {
                    return NTStatus.SEC_E_INVALID_TOKEN;
                }

                SessionSetupAndXRequestExtended request = new SessionSetupAndXRequestExtended();
                request.MaxBufferSize = ClientMaxBufferSize;
                request.MaxMpxCount = m_maxMpxCount;
                request.Capabilities = clientCapabilities;
                request.SecurityBlob = negotiateMessage;
                TrySendMessage(request);
                
                SMB1Message reply = WaitForMessage(CommandName.SMB_COM_SESSION_SETUP_ANDX);
                if (reply != null)
                {
                    if (reply.Header.Status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED && reply.Commands[0] is SessionSetupAndXResponseExtended)
                    {
                        SessionSetupAndXResponseExtended response = (SessionSetupAndXResponseExtended)reply.Commands[0];
                        byte[] authenticateMessage = NTLMAuthenticationHelper.GetAuthenticateMessage(response.SecurityBlob, domainName, userName, password, authenticationMethod, out m_sessionKey);
                        if (authenticateMessage == null)
                        {
                            return NTStatus.SEC_E_INVALID_TOKEN;
                        }

                        m_userID = reply.Header.UID;
                        request = new SessionSetupAndXRequestExtended();
                        request.MaxBufferSize = ClientMaxBufferSize;
                        request.MaxMpxCount = m_maxMpxCount;
                        request.Capabilities = clientCapabilities;
                        request.SecurityBlob = authenticateMessage;
                        TrySendMessage(request);

                        reply = WaitForMessage(CommandName.SMB_COM_SESSION_SETUP_ANDX);
                        if (reply != null)
                        {
                            m_isLoggedIn = (reply.Header.Status == NTStatus.STATUS_SUCCESS);
                            return reply.Header.Status;
                        }
                    }
                    else
                    {
                        return reply.Header.Status;
                    }
                }
                return NTStatus.STATUS_INVALID_SMB;
            }
        }

        public NTStatus Logoff()
        {
            if (!m_isConnected)
            {
                throw new InvalidOperationException("A login session must be successfully established before attempting logoff");
            }

            LogoffAndXRequest request = new LogoffAndXRequest();
            TrySendMessage(request);

            SMB1Message reply = WaitForMessage(CommandName.SMB_COM_LOGOFF_ANDX);
            if (reply != null)
            {
                m_isLoggedIn = (reply.Header.Status != NTStatus.STATUS_SUCCESS);
                return reply.Header.Status;
            }
            return NTStatus.STATUS_INVALID_SMB;
        }

        public List<ShareInfo2Entry> ListShares(out NTStatus status)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before retrieving share list");
            }

            SMB1FileStore namedPipeShare = TreeConnect("IPC$", ServiceName.NamedPipe, out status);
            if (namedPipeShare == null)
            {
                return null;
            }

            List<ShareInfo2Entry> shares = ServerServiceHelper.ListShares(namedPipeShare, ShareType.DiskDrive, out status);
            namedPipeShare.Disconnect();
            return shares;
        }

        public ISMBFileStore TreeConnect(string shareName, out NTStatus status)
        {
            return TreeConnect(shareName, ServiceName.AnyType, out status);
        }

        public SMB1FileStore TreeConnect(string shareName, ServiceName serviceName, out NTStatus status)
        {
            if (!m_isConnected || !m_isLoggedIn)
            {
                throw new InvalidOperationException("A login session must be successfully established before connecting to a share");
            }

            TreeConnectAndXRequest request = new TreeConnectAndXRequest();
            request.Path = shareName;
            request.Service = serviceName;
            TrySendMessage(request);
            SMB1Message reply = WaitForMessage(CommandName.SMB_COM_TREE_CONNECT_ANDX);
            if (reply != null)
            {
                status = reply.Header.Status;
                if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is TreeConnectAndXResponse)
                {
                    TreeConnectAndXResponse response = (TreeConnectAndXResponse)reply.Commands[0];
                    return new SMB1FileStore(this, reply.Header.TID);
                }
            }
            else
            {
                status = NTStatus.STATUS_INVALID_SMB;
            }
            return null;
        }

        private void OnClientSocketReceive(IAsyncResult ar)
        {
            ConnectionState state = (ConnectionState)ar.AsyncState;
            Socket clientSocket = state.ClientSocket;

            if (!clientSocket.Connected)
            {
                return;
            }

            int numberOfBytesReceived = 0;
            try
            {
                numberOfBytesReceived = clientSocket.EndReceive(ar);
            }
            catch (ArgumentException) // The IAsyncResult object was not returned from the corresponding synchronous method on this class.
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                Log("[ReceiveCallback] EndReceive ObjectDisposedException");
                return;
            }
            catch (SocketException ex)
            {
                Log("[ReceiveCallback] EndReceive SocketException: " + ex.Message);
                return;
            }

            if (numberOfBytesReceived == 0)
            {
                m_isConnected = false;
            }
            else
            {
                NBTConnectionReceiveBuffer buffer = state.ReceiveBuffer;
                buffer.SetNumberOfBytesReceived(numberOfBytesReceived);
                ProcessConnectionBuffer(state);

                try
                {
                    clientSocket.BeginReceive(buffer.Buffer, buffer.WriteOffset, buffer.AvailableLength, SocketFlags.None, new AsyncCallback(OnClientSocketReceive), state);
                }
                catch (ObjectDisposedException)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] BeginReceive ObjectDisposedException");
                }
                catch (SocketException ex)
                {
                    m_isConnected = false;
                    Log("[ReceiveCallback] BeginReceive SocketException: " + ex.Message);
                }
            }
        }

        private void ProcessConnectionBuffer(ConnectionState state)
        {
            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket packet = null;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception)
                {
                    state.ClientSocket.Close();
                    break;
                }

                if (packet != null)
                {
                    ProcessPacket(packet, state);
                }
            }
        }

        private void ProcessPacket(SessionPacket packet, ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                SMB1Message message;
                try
                {
                    message = SMB1Message.GetSMB1Message(packet.Trailer);
                }
                catch (Exception ex)
                {
                    Log("Invalid SMB1 message: " + ex.Message);
                    state.ClientSocket.Close();
                    m_isConnected = false;
                    return;
                }

                // [MS-CIFS] 3.2.5.1 - If the MID value is the reserved value 0xFFFF, the message can be an OpLock break
                // sent by the server. Otherwise, if the PID and MID values of the received message are not found in the
                // Client.Connection.PIDMIDList, the message MUST be discarded.
                if ((message.Header.MID == 0xFFFF && message.Header.Command == CommandName.SMB_COM_LOCKING_ANDX) ||
                    (message.Header.PID == 0 && message.Header.MID == 0))
                {
                    lock (m_incomingQueueLock)
                    {
                        m_incomingQueue.Add(message);
                        m_incomingQueueEventHandle.Set();
                    }
                }
            }
            else if ((packet is PositiveSessionResponsePacket || packet is NegativeSessionResponsePacket) && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                m_sessionResponsePacket = packet;
                m_sessionResponseEventHandle.Set();
            }
            else if (packet is SessionKeepAlivePacket && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                Log("Inappropriate NetBIOS session packet");
                state.ClientSocket.Close();
            }
        }

        internal SMB1Message WaitForMessage(CommandName commandName)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < ResponseTimeoutInMilliseconds)
            {
                lock (m_incomingQueueLock)
                {
                    for (int index = 0; index < m_incomingQueue.Count; index++)
                    {
                        SMB1Message message = m_incomingQueue[index];

                        if (message.Commands[0].CommandName == commandName)
                        {
                            m_incomingQueue.RemoveAt(index);
                            return message;
                        }
                    }
                }
                m_incomingQueueEventHandle.WaitOne(100);
            }
            return null;
        }

        internal SessionPacket WaitForSessionResponsePacket()
        {
            const int TimeOut = 5000;
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (stopwatch.ElapsedMilliseconds < TimeOut)
            {
                if (m_sessionResponsePacket != null)
                {
                    SessionPacket result = m_sessionResponsePacket;
                    m_sessionResponsePacket = null;
                    return result;
                }

                m_sessionResponseEventHandle.WaitOne(100);
            }

            return null;
        }

        private void Log(string message)
        {
            System.Diagnostics.Debug.Print(message);
        }

        internal void TrySendMessage(SMB1Command request)
        {
            TrySendMessage(request, 0);
        }

        internal void TrySendMessage(SMB1Command request, ushort treeID)
        {
            SMB1Message message = new SMB1Message();
            message.Header.UnicodeFlag = m_unicode;
            message.Header.ExtendedSecurityFlag = m_forceExtendedSecurity;
            message.Header.Flags2 |= HeaderFlags2.LongNamesAllowed | HeaderFlags2.LongNameUsed | HeaderFlags2.NTStatusCode;
            message.Header.UID = m_userID;
            message.Header.TID = treeID;
            message.Commands.Add(request);
            TrySendMessage(m_clientSocket, message);
        }

        public bool Unicode
        {
            get
            {
                return m_unicode;
            }
        }

        public bool LargeFiles
        {
            get
            {
                return m_largeFiles;
            }
        }

        public bool InfoLevelPassthrough
        {
            get
            {
                return m_infoLevelPassthrough;
            }
        }

        public bool LargeRead
        {
            get
            {
                return m_largeRead;
            }
        }

        public bool LargeWrite
        {
            get
            {
                return m_largeWrite;
            }
        }

        public uint ServerMaxBufferSize
        {
            get
            {
                return m_serverMaxBufferSize;
            }
        }

        public int MaxMpxCount
        {
            get
            {
                return m_maxMpxCount;
            }
        }

        public uint MaxReadSize
        {
            get
            {
                return (uint)ClientMaxBufferSize - (SMB1Header.Length + 3 + ReadAndXResponse.ParametersLength);
            }
        }

        public uint MaxWriteSize
        {
            get
            {
                uint result = ServerMaxBufferSize - (SMB1Header.Length + 3 + WriteAndXRequest.ParametersFixedLength + 4);
                if (m_unicode)
                {
                    result--;
                }
                return result;
            }
        }

        public static void TrySendMessage(Socket socket, SMB1Message message)
        {
            SessionMessagePacket packet = new SessionMessagePacket();
            packet.Trailer = message.GetBytes();
            TrySendPacket(socket, packet);
        }

        public static void TrySendPacket(Socket socket, SessionPacket packet)
        {
            try
            {
                byte[] packetBytes = packet.GetBytes();
                socket.Send(packetBytes);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }
}
