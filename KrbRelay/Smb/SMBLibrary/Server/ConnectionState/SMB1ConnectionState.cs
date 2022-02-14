/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace SMBLibrary.Server
{
    internal class SMB1ConnectionState : ConnectionState
    {
        public int MaxBufferSize;
        public bool LargeRead;
        public bool LargeWrite;

        // Key is UID
        private Dictionary<ushort, SMB1Session> m_sessions = new Dictionary<ushort, SMB1Session>();

        private ushort m_nextUID = 1; // UID MUST be unique within an SMB connection
        private ushort m_nextTID = 1; // TID MUST be unique within an SMB connection
        private ushort m_nextFID = 1; // FID MUST be unique within an SMB connection

        // Key is PID (PID MUST be unique within an SMB connection)
        private Dictionary<uint, ProcessStateObject> m_processStateList = new Dictionary<uint, ProcessStateObject>();

        private List<SMB1AsyncContext> m_pendingRequests = new List<SMB1AsyncContext>();

        public SMB1ConnectionState(ConnectionState state) : base(state)
        {
        }

        /// <summary>
        /// An open UID MUST be unique within an SMB connection.
        /// The value of 0xFFFE SHOULD NOT be used as a valid UID. All other possible values for a UID, excluding zero (0x0000), are valid.
        /// </summary>
        public ushort? AllocateUserID()
        {
            for (ushort offset = 0; offset < UInt16.MaxValue; offset++)
            {
                ushort userID = (ushort)(m_nextUID + offset);
                if (userID == 0 || userID == 0xFFFE || userID == 0xFFFF)
                {
                    continue;
                }
                if (!m_sessions.ContainsKey(userID))
                {
                    m_nextUID = (ushort)(userID + 1);
                    return userID;
                }
            }
            return null;
        }

        public SMB1Session CreateSession(ushort userID, string userName, string machineName, byte[] sessionKey, object accessToken)
        {
            SMB1Session session = new SMB1Session(this, userID, userName, machineName, sessionKey, accessToken);
            lock (m_sessions)
            {
                m_sessions.Add(userID, session);
            }
            return session;
        }

        /// <returns>null if all UserID values have already been allocated</returns>
        public SMB1Session CreateSession(string userName, string machineName, byte[] sessionKey, object accessToken)
        {
            ushort? userID = AllocateUserID();
            if (userID.HasValue)
            {
                return CreateSession(userID.Value, userName, machineName, sessionKey, accessToken);
            }
            return null;
        }

        public SMB1Session GetSession(ushort userID)
        {
            SMB1Session session;
            m_sessions.TryGetValue(userID, out session);
            return session;
        }

        public void RemoveSession(ushort userID)
        {
            SMB1Session session;
            m_sessions.TryGetValue(userID, out session);
            if (session != null)
            {
                session.Close();
                lock (m_sessions)
                {
                    m_sessions.Remove(userID);
                }
            }
        }

        public override void CloseSessions()
        {
            lock (m_sessions)
            {
                foreach (SMB1Session session in m_sessions.Values)
                {
                    session.Close();
                }

                m_sessions.Clear();
            }
        }

        public override List<SessionInformation> GetSessionsInformation()
        {
            List<SessionInformation> result = new List<SessionInformation>();
            lock (m_sessions)
            {
                foreach (SMB1Session session in m_sessions.Values)
                {
                    result.Add(new SessionInformation(this.ClientEndPoint, this.Dialect, session.UserName, session.MachineName, session.GetOpenFilesInformation(), session.CreationDT));
                }
            }
            return result;
        }

        /// <summary>
        /// An open TID MUST be unique within an SMB connection.
        /// The value 0xFFFF MUST NOT be used as a valid TID. All other possible values for TID, including zero (0x0000), are valid.
        /// </summary>
        public ushort? AllocateTreeID()
        {
            for (ushort offset = 0; offset < UInt16.MaxValue; offset++)
            {
                ushort treeID = (ushort)(m_nextTID + offset);
                if (treeID == 0 || treeID == 0xFFFF)
                {
                    continue;
                }
                if (!IsTreeIDAllocated(treeID))
                {
                    m_nextTID = (ushort)(treeID + 1);
                    return treeID;
                }
            }
            return null;
        }

        private bool IsTreeIDAllocated(ushort treeID)
        {
            foreach (SMB1Session session in m_sessions.Values)
            {
                if (session.GetConnectedTree(treeID) != null)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// A FID returned from an Open or Create operation MUST be unique within an SMB connection.
        /// The value 0xFFFF MUST NOT be used as a valid FID. All other possible values for FID, including zero (0x0000) are valid.
        /// </summary>
        /// <returns></returns>
        public ushort? AllocateFileID()
        {
            for (ushort offset = 0; offset < UInt16.MaxValue; offset++)
            {
                ushort fileID = (ushort)(m_nextFID + offset);
                if (fileID == 0 || fileID == 0xFFFF)
                {
                    continue;
                }
                if (!IsFileIDAllocated(fileID))
                {
                    m_nextFID = (ushort)(fileID + 1);
                    return fileID;
                }
            }
            return null;
        }

        private bool IsFileIDAllocated(ushort fileID)
        {
            foreach (SMB1Session session in m_sessions.Values)
            {
                if (session.GetOpenFileObject(fileID) != null)
                {
                    return true;
                }
            }
            return false;
        }

        public ProcessStateObject CreateProcessState(uint processID)
        {
            ProcessStateObject processState = new ProcessStateObject();
            m_processStateList[processID] = processState;
            return processState;
        }

        public ProcessStateObject GetProcessState(uint processID)
        {
            if (m_processStateList.ContainsKey(processID))
            {
                return m_processStateList[processID];
            }
            else
            {
                return null;
            }
        }

        public void RemoveProcessState(uint processID)
        {
            m_processStateList.Remove(processID);
        }

        public SMB1AsyncContext CreateAsyncContext(ushort userID, ushort treeID, uint processID, ushort multiplexID, ushort fileID, SMB1ConnectionState connection)
        {
            SMB1AsyncContext context = new SMB1AsyncContext();
            context.UID = userID;
            context.TID = treeID;
            context.MID = multiplexID;
            context.PID = processID;
            context.FileID = fileID;
            context.Connection = connection;
            lock (m_pendingRequests)
            {
                m_pendingRequests.Add(context);
            }
            return context;
        }

        public SMB1AsyncContext GetAsyncContext(ushort userID, ushort treeID, uint processID, ushort multiplexID)
        {
            lock (m_pendingRequests)
            {
                int index = IndexOfAsyncContext(userID, treeID, processID, multiplexID);
                if (index >= 0)
                {
                    return m_pendingRequests[index];
                }
            }
            return null;
        }

        public void RemoveAsyncContext(SMB1AsyncContext context)
        {
            lock (m_pendingRequests)
            {
                int index = IndexOfAsyncContext(context.UID, context.TID, context.PID, context.MID);
                if (index >= 0)
                {
                    m_pendingRequests.RemoveAt(index);
                }
            }
        }

        private int IndexOfAsyncContext(ushort userID, ushort treeID, uint processID, ushort multiplexID)
        {
            for (int index = 0; index < m_pendingRequests.Count; index++)
            {
                SMB1AsyncContext context = m_pendingRequests[index];
                if (context.UID == userID &&
                    context.TID == treeID &&
                    context.PID == processID &&
                    context.MID == multiplexID)
                {
                    return index;
                }
            }

            return -1;
        }
    }
}