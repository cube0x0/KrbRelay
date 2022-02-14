/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Net;
using Utilities;

namespace SMBLibrary.Server
{
    internal class ConnectionManager
    {
        private List<ConnectionState> m_activeConnections = new List<ConnectionState>();

        public void AddConnection(ConnectionState connection)
        {
            lock (m_activeConnections)
            {
                m_activeConnections.Add(connection);
            }
        }

        public bool RemoveConnection(ConnectionState connection)
        {
            lock (m_activeConnections)
            {
                int connectionIndex = m_activeConnections.IndexOf(connection);
                if (connectionIndex >= 0)
                {
                    m_activeConnections.RemoveAt(connectionIndex);
                    return true;
                }
                return false;
            }
        }

        public void ReleaseConnection(ConnectionState connection)
        {
            connection.SendQueue.Stop();
            SocketUtils.ReleaseSocket(connection.ClientSocket);
            connection.CloseSessions();
            RemoveConnection(connection);
        }

        public void ReleaseConnection(IPEndPoint clientEndPoint)
        {
            ConnectionState connection = FindConnection(clientEndPoint);
            if (connection != null)
            {
                ReleaseConnection(connection);
            }
        }

        /// <summary>
        /// Some broken NATs will reply to TCP KeepAlive even after the client initiating the connection has long gone,
        /// This methods prevent such connections from hanging around indefinitely by sending an unsolicited ECHO response to make sure the connection is still alive.
        /// </summary>
        public void SendSMBKeepAlive(TimeSpan inactivityDuration)
        {
            List<ConnectionState> connections = new List<ConnectionState>(m_activeConnections);
            foreach (ConnectionState connection in connections)
            {
                if (connection.LastReceiveDT.Add(inactivityDuration) < DateTime.UtcNow &&
                    connection.LastSendDT.Add(inactivityDuration) < DateTime.UtcNow)
                {
                    if (connection is SMB1ConnectionState)
                    {
                        // [MS-CIFS] Clients SHOULD, at minimum, send an SMB_COM_ECHO to the server every few minutes.
                        // This means that an unsolicited SMB_COM_ECHO reply is not likely to be sent on a connection that is alive.
                        SMBLibrary.SMB1.SMB1Message echoReply = SMB1.EchoHelper.GetUnsolicitedEchoReply();
                        SMBServer.EnqueueMessage(connection, echoReply);
                    }
                    else if (connection is SMB2ConnectionState)
                    {
                        SMBLibrary.SMB2.EchoResponse echoResponse = SMB2.EchoHelper.GetUnsolicitedEchoResponse();
                        SMBServer.EnqueueResponse(connection, echoResponse);
                    }
                }
            }
        }

        public void ReleaseAllConnections()
        {
            List<ConnectionState> connections = new List<ConnectionState>(m_activeConnections);
            foreach (ConnectionState connection in connections)
            {
                ReleaseConnection(connection);
            }
        }

        private ConnectionState FindConnection(IPEndPoint clientEndPoint)
        {
            lock (m_activeConnections)
            {
                for (int index = 0; index < m_activeConnections.Count; index++)
                {
                    if (m_activeConnections[index].ClientEndPoint.Equals(clientEndPoint))
                    {
                        return m_activeConnections[index];
                    }
                }
            }
            return null;
        }

        public List<SessionInformation> GetSessionsInformation()
        {
            List<SessionInformation> result = new List<SessionInformation>();
            lock (m_activeConnections)
            {
                foreach (ConnectionState connection in m_activeConnections)
                {
                    List<SessionInformation> sessions = connection.GetSessionsInformation();
                    result.AddRange(sessions);
                }
            }
            return result;
        }
    }
}