/* Copyright (C) 2014-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.NetBios;
using SMBLibrary.SMB1;
using SMBLibrary.SMB2;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Utilities;

namespace SMBLibrary.Server
{
    public partial class SMBServer
    {
        public static readonly int NetBiosOverTCPPort = 139;
        public static readonly int DirectTCPPort = 445;
        public const string NTLanManagerDialect = "NT LM 0.12";
        public static readonly bool EnableExtendedSecurity = true;
        private static readonly int InactivityMonitoringInterval = 30000; // Check every 30 seconds

        private SMBShareCollection m_shares; // e.g. Shared folders
        private GSSProvider m_securityProvider;
        private NamedPipeShare m_services; // Named pipes
        private Guid m_serverGuid;

        private ConnectionManager m_connectionManager;
        private Thread m_sendSMBKeepAliveThread;

        private IPAddress m_serverAddress;
        private SMBTransportType m_transport;
        private bool m_enableSMB1;
        private bool m_enableSMB2;
        private bool m_enableSMB3;
        private Socket m_listenerSocket;
        private bool m_listening;
        private DateTime m_serverStartTime;

        public event EventHandler<ConnectionRequestEventArgs> ConnectionRequested;

        public event EventHandler<LogEntry> LogEntryAdded;

        public SMBServer(SMBShareCollection shares, GSSProvider securityProvider)
        {
            m_shares = shares;
            m_securityProvider = securityProvider;
            m_services = new NamedPipeShare(shares.ListShares());
            m_serverGuid = Guid.NewGuid();
            m_connectionManager = new ConnectionManager();
        }

        public void Start(IPAddress serverAddress, SMBTransportType transport)
        {
            Start(serverAddress, transport, true, true);
        }

        public void Start(IPAddress serverAddress, SMBTransportType transport, bool enableSMB1, bool enableSMB2)
        {
            Start(serverAddress, transport, enableSMB1, enableSMB2, false);
        }

        public void Start(IPAddress serverAddress, SMBTransportType transport, bool enableSMB1, bool enableSMB2, bool enableSMB3)
        {
            Start(serverAddress, transport, enableSMB1, enableSMB2, enableSMB3, null);
        }

        /// <param name="connectionInactivityTimeout">
        /// The duration after which an unsolicited ECHO response will be sent if no data has been sent or received.
        /// Some broken NATs will reply to TCP KeepAlive even after the client initiating the connection has long gone,
        /// to prevent such connections from hanging around indefinitely, this parameter can be used.
        /// </param>
        /// <exception cref="System.Net.Sockets.SocketException"></exception>
        public void Start(IPAddress serverAddress, SMBTransportType transport, bool enableSMB1, bool enableSMB2, bool enableSMB3, TimeSpan? connectionInactivityTimeout)
        {
            int port = (transport == SMBTransportType.DirectTCPTransport ? DirectTCPPort : NetBiosOverTCPPort);
            Start(serverAddress, transport, port, enableSMB1, enableSMB2, enableSMB3, connectionInactivityTimeout);
        }

        private void Start(IPAddress serverAddress, SMBTransportType transport, int port, bool enableSMB1, bool enableSMB2, bool enableSMB3, TimeSpan? connectionInactivityTimeout)
        {
            if (!m_listening)
            {
                if (enableSMB3 && !enableSMB2)
                {
                    throw new ArgumentException("SMB2 must be enabled for SMB3 to be enabled");
                }

                Log(Severity.Information, "Starting server");
                m_serverAddress = serverAddress;
                m_transport = transport;
                m_enableSMB1 = enableSMB1;
                m_enableSMB2 = enableSMB2;
                m_enableSMB3 = enableSMB3;
                m_listening = true;
                m_serverStartTime = DateTime.Now;

                m_listenerSocket = new Socket(m_serverAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                m_listenerSocket.Bind(new IPEndPoint(m_serverAddress, port));
                m_listenerSocket.Listen((int)SocketOptionName.MaxConnections);
                m_listenerSocket.BeginAccept(ConnectRequestCallback, m_listenerSocket);

                if (connectionInactivityTimeout.HasValue)
                {
                    m_sendSMBKeepAliveThread = new Thread(delegate ()
                    {
                        while (m_listening)
                        {
                            Thread.Sleep(InactivityMonitoringInterval);
                            m_connectionManager.SendSMBKeepAlive(connectionInactivityTimeout.Value);
                        }
                    });
                    m_sendSMBKeepAliveThread.IsBackground = true;
                    m_sendSMBKeepAliveThread.Start();
                }
            }
        }

        public void Stop()
        {
            Log(Severity.Information, "Stopping server");
            m_listening = false;
            if (m_sendSMBKeepAliveThread != null)
            {
                m_sendSMBKeepAliveThread.Abort();
            }
            SocketUtils.ReleaseSocket(m_listenerSocket);
            m_connectionManager.ReleaseAllConnections();
        }

        // This method accepts new connections
        private void ConnectRequestCallback(IAsyncResult ar)
        {
            Socket listenerSocket = (Socket)ar.AsyncState;

            Socket clientSocket;
            try
            {
                clientSocket = listenerSocket.EndAccept(ar);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                const int WSAECONNRESET = 10054; // The client may have closed the connection before we start to process the connection request.
                const int WSAETIMEDOUT = 10060; // The client did not properly respond after a period of time.
                // When we get WSAECONNRESET or WSAETIMEDOUT, we have to continue to accept other connection requests.
                // See http://stackoverflow.com/questions/7704417/socket-endaccept-error-10054
                if (ex.ErrorCode == WSAECONNRESET || ex.ErrorCode == WSAETIMEDOUT)
                {
                    listenerSocket.BeginAccept(ConnectRequestCallback, listenerSocket);
                }
                Log(Severity.Debug, "Connection request error {0}", ex.ErrorCode);
                return;
            }

            // Windows will set the TCP keepalive timeout to 120 seconds for an SMB connection
            SocketUtils.SetKeepAlive(clientSocket, TimeSpan.FromMinutes(2));
            // Disable the Nagle Algorithm for this tcp socket:
            clientSocket.NoDelay = true;
            IPEndPoint clientEndPoint = (IPEndPoint)clientSocket.RemoteEndPoint;
            EventHandler<ConnectionRequestEventArgs> handler = ConnectionRequested;
            bool acceptConnection = true;
            if (handler != null)
            {
                ConnectionRequestEventArgs connectionRequestArgs = new ConnectionRequestEventArgs(clientEndPoint);
                handler(this, connectionRequestArgs);
                acceptConnection = connectionRequestArgs.Accept;
            }

            if (acceptConnection)
            {
                ConnectionState state = new ConnectionState(clientSocket, clientEndPoint, Log);
                state.LogToServer(Severity.Verbose, "New connection request accepted");
                Thread senderThread = new Thread(delegate ()
                {
                    ProcessSendQueue(state);
                });
                senderThread.IsBackground = true;
                senderThread.Start();

                try
                {
                    // Direct TCP transport packet is actually an NBT Session Message Packet,
                    // So in either case (NetBios over TCP or Direct TCP Transport) we will receive an NBT packet.
                    clientSocket.BeginReceive(state.ReceiveBuffer.Buffer, state.ReceiveBuffer.WriteOffset, state.ReceiveBuffer.AvailableLength, 0, ReceiveCallback, state);
                }
                catch (ObjectDisposedException)
                {
                }
                catch (SocketException)
                {
                }
            }
            else
            {
                Log(Severity.Verbose, "[{0}:{1}] New connection request rejected", clientEndPoint.Address, clientEndPoint.Port);
                clientSocket.Close();
            }

            listenerSocket.BeginAccept(ConnectRequestCallback, listenerSocket);
        }

        private void ReceiveCallback(IAsyncResult result)
        {
            ConnectionState state = (ConnectionState)result.AsyncState;
            Socket clientSocket = state.ClientSocket;

            if (!m_listening)
            {
                clientSocket.Close();
                return;
            }

            int numberOfBytesReceived;
            try
            {
                numberOfBytesReceived = clientSocket.EndReceive(result);
            }
            catch (ObjectDisposedException)
            {
                state.LogToServer(Severity.Debug, "The connection was terminated");
                m_connectionManager.ReleaseConnection(state);
                return;
            }
            catch (SocketException ex)
            {
                const int WSAECONNRESET = 10054;
                if (ex.ErrorCode == WSAECONNRESET)
                {
                    state.LogToServer(Severity.Debug, "The connection was forcibly closed by the remote host");
                }
                else
                {
                    state.LogToServer(Severity.Debug, "The connection was terminated, Socket error code: {0}", ex.ErrorCode);
                }
                m_connectionManager.ReleaseConnection(state);
                return;
            }

            if (numberOfBytesReceived == 0)
            {
                state.LogToServer(Severity.Debug, "The client closed the connection");
                m_connectionManager.ReleaseConnection(state);
                return;
            }

            state.UpdateLastReceiveDT();
            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            receiveBuffer.SetNumberOfBytesReceived(numberOfBytesReceived);
            ProcessConnectionBuffer(ref state);

            if (clientSocket.Connected)
            {
                try
                {
                    clientSocket.BeginReceive(state.ReceiveBuffer.Buffer, state.ReceiveBuffer.WriteOffset, state.ReceiveBuffer.AvailableLength, 0, ReceiveCallback, state);
                }
                catch (ObjectDisposedException)
                {
                    m_connectionManager.ReleaseConnection(state);
                }
                catch (SocketException)
                {
                    m_connectionManager.ReleaseConnection(state);
                }
            }
        }

        private void ProcessConnectionBuffer(ref ConnectionState state)
        {
            Socket clientSocket = state.ClientSocket;

            NBTConnectionReceiveBuffer receiveBuffer = state.ReceiveBuffer;
            while (receiveBuffer.HasCompletePacket())
            {
                SessionPacket packet = null;
                try
                {
                    packet = receiveBuffer.DequeuePacket();
                }
                catch (Exception ex)
                {
                    state.ClientSocket.Close();
                    state.LogToServer(Severity.Warning, "Rejected Invalid NetBIOS session packet: {0}", ex.Message);
                    break;
                }

                if (packet != null)
                {
                    ProcessPacket(packet, ref state);
                }
            }
        }

        private void ProcessPacket(SessionPacket packet, ref ConnectionState state)
        {
            if (packet is SessionMessagePacket)
            {
                // Note: To be compatible with SMB2 specifications, we must accept SMB_COM_NEGOTIATE.
                // We will disconnect the connection if m_enableSMB1 == false and the client does not support SMB2.
                bool acceptSMB1 = (state.Dialect == SMBDialect.NotSet || state.Dialect == SMBDialect.NTLM012);
                bool acceptSMB2 = (m_enableSMB2 && (state.Dialect == SMBDialect.NotSet || state.Dialect == SMBDialect.SMB202 || state.Dialect == SMBDialect.SMB210 || state.Dialect == SMBDialect.SMB300));

                if (SMB1Header.IsValidSMB1Header(packet.Trailer))
                {
                    if (!acceptSMB1)
                    {
                        state.LogToServer(Severity.Verbose, "Rejected SMB1 message");
                        state.ClientSocket.Close();
                        return;
                    }

                    SMB1Message message = null;
                    try
                    {
                        message = SMB1Message.GetSMB1Message(packet.Trailer);
                    }
                    catch (Exception ex)
                    {
                        state.LogToServer(Severity.Warning, "Invalid SMB1 message: " + ex.Message);
                        state.ClientSocket.Close();
                        return;
                    }
                    state.LogToServer(Severity.Verbose, "SMB1 message received: {0} requests, First request: {1}, Packet length: {2}", message.Commands.Count, message.Commands[0].CommandName.ToString(), packet.Length);
                    if (state.Dialect == SMBDialect.NotSet && m_enableSMB2)
                    {
                        // Check if the client supports SMB 2
                        List<string> smb2Dialects = SMB2.NegotiateHelper.FindSMB2Dialects(message);
                        if (smb2Dialects.Count > 0)
                        {
                            SMB2Command response = SMB2.NegotiateHelper.GetNegotiateResponse(smb2Dialects, m_securityProvider, state, m_transport, m_serverGuid, m_serverStartTime);
                            if (state.Dialect != SMBDialect.NotSet)
                            {
                                state = new SMB2ConnectionState(state);
                                m_connectionManager.AddConnection(state);
                            }
                            EnqueueResponse(state, response);
                            return;
                        }
                    }

                    if (m_enableSMB1)
                    {
                        ProcessSMB1Message(message, ref state);
                    }
                    else
                    {
                        // [MS-SMB2] 3.3.5.3.2 If the string is not present in the dialect list and the server does not implement SMB,
                        // the server MUST disconnect the connection [..] without sending a response.
                        state.LogToServer(Severity.Verbose, "Rejected SMB1 message");
                        state.ClientSocket.Close();
                    }
                }
                else if (SMB2Header.IsValidSMB2Header(packet.Trailer))
                {
                    if (!acceptSMB2)
                    {
                        state.LogToServer(Severity.Verbose, "Rejected SMB2 message");
                        state.ClientSocket.Close();
                        return;
                    }

                    List<SMB2Command> requestChain;
                    try
                    {
                        requestChain = SMB2Command.ReadRequestChain(packet.Trailer, 0);
                    }
                    catch (Exception ex)
                    {
                        state.LogToServer(Severity.Warning, "Invalid SMB2 request chain: " + ex.Message);
                        state.ClientSocket.Close();
                        return;
                    }
                    state.LogToServer(Severity.Verbose, "SMB2 request chain received: {0} requests, First request: {1}, Packet length: {2}", requestChain.Count, requestChain[0].CommandName.ToString(), packet.Length);
                    ProcessSMB2RequestChain(requestChain, ref state);
                }
                else
                {
                    state.LogToServer(Severity.Warning, "Invalid SMB message");
                    state.ClientSocket.Close();
                }
            }
            else if (packet is SessionRequestPacket && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                PositiveSessionResponsePacket response = new PositiveSessionResponsePacket();
                state.SendQueue.Enqueue(response);
            }
            else if (packet is SessionKeepAlivePacket && m_transport == SMBTransportType.NetBiosOverTCP)
            {
                // [RFC 1001] NetBIOS session keep alives do not require a response from the NetBIOS peer
            }
            else
            {
                state.LogToServer(Severity.Warning, "Inappropriate NetBIOS session packet");
                state.ClientSocket.Close();
                return;
            }
        }

        private void ProcessSendQueue(ConnectionState state)
        {
            state.LogToServer(Severity.Trace, "Entering ProcessSendQueue");
            while (true)
            {
                SessionPacket response;
                bool stopped = !state.SendQueue.TryDequeue(out response);
                if (stopped)
                {
                    return;
                }
                Socket clientSocket = state.ClientSocket;
                try
                {
                    byte[] responseBytes = response.GetBytes();
                    clientSocket.Send(responseBytes);
                }
                catch (SocketException ex)
                {
                    state.LogToServer(Severity.Debug, "Failed to send packet. SocketException: {0}", ex.Message);
                    // Note: m_connectionManager contains SMB1ConnectionState or SMB2ConnectionState instances that were constructed from the initial
                    // ConnectionState instance given to this method. for this reason, we must use state.ClientEndPoint to find and release the connection.
                    m_connectionManager.ReleaseConnection(state.ClientEndPoint);
                    return;
                }
                catch (ObjectDisposedException)
                {
                    state.LogToServer(Severity.Debug, "Failed to send packet. ObjectDisposedException.");
                    m_connectionManager.ReleaseConnection(state.ClientEndPoint);
                    return;
                }
                state.UpdateLastSendDT();
            }
        }

        public List<SessionInformation> GetSessionsInformation()
        {
            return m_connectionManager.GetSessionsInformation();
        }

        public void TerminateConnection(IPEndPoint clientEndPoint)
        {
            m_connectionManager.ReleaseConnection(clientEndPoint);
        }

        private void Log(Severity severity, string message)
        {
            // To be thread-safe we must capture the delegate reference first
            EventHandler<LogEntry> handler = LogEntryAdded;
            if (handler != null)
            {
                handler(this, new LogEntry(DateTime.Now, severity, "SMB Server", message));
            }
        }

        private void Log(Severity severity, string message, params object[] args)
        {
            Log(severity, String.Format(message, args));
        }
    }
}