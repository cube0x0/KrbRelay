/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.IO;

namespace SMBLibrary.Server
{
    internal class SMB1Session
    {
        private const int MaxSearches = 2048; // Windows servers initialize Server.MaxSearches to 2048.

        private SMB1ConnectionState m_connection;
        private ushort m_userID;
        private byte[] m_sessionKey;
        private SecurityContext m_securityContext;
        private DateTime m_creationDT;

        // Key is TID
        private Dictionary<ushort, ISMBShare> m_connectedTrees = new Dictionary<ushort, ISMBShare>();

        // Key is FID
        private Dictionary<ushort, OpenFileObject> m_openFiles = new Dictionary<ushort, OpenFileObject>();

        // Key is search handle a.k.a. Search ID
        private Dictionary<ushort, OpenSearch> m_openSearches = new Dictionary<ushort, OpenSearch>();

        private ushort m_nextSearchHandle = 1;

        public SMB1Session(SMB1ConnectionState connection, ushort userID, string userName, string machineName, byte[] sessionKey, object accessToken)
        {
            m_connection = connection;
            m_userID = userID;
            m_sessionKey = sessionKey;
            m_securityContext = new SecurityContext(userName, machineName, connection.ClientEndPoint, connection.AuthenticationContext, accessToken);
            m_creationDT = DateTime.UtcNow;
        }

        public ushort? AddConnectedTree(ISMBShare share)
        {
            lock (m_connection)
            {
                ushort? treeID = m_connection.AllocateTreeID();
                if (treeID.HasValue)
                {
                    m_connectedTrees.Add(treeID.Value, share);
                }
                return treeID;
            }
        }

        public ISMBShare GetConnectedTree(ushort treeID)
        {
            ISMBShare share;
            m_connectedTrees.TryGetValue(treeID, out share);
            return share;
        }

        public void DisconnectTree(ushort treeID)
        {
            ISMBShare share;
            m_connectedTrees.TryGetValue(treeID, out share);
            if (share != null)
            {
                lock (m_connection)
                {
                    List<ushort> fileIDList = new List<ushort>(m_openFiles.Keys);
                    foreach (ushort fileID in fileIDList)
                    {
                        OpenFileObject openFile = m_openFiles[fileID];
                        if (openFile.TreeID == treeID)
                        {
                            share.FileStore.CloseFile(openFile.Handle);
                            m_openFiles.Remove(fileID);
                        }
                    }
                    m_connectedTrees.Remove(treeID);
                }
            }
        }

        public bool IsTreeConnected(ushort treeID)
        {
            return m_connectedTrees.ContainsKey(treeID);
        }

        /// <param name="relativePath">The path relative to the share</param>
        /// <returns>FileID</returns>
        public ushort? AddOpenFile(ushort treeID, string shareName, string relativePath, object handle, FileAccess fileAccess)
        {
            lock (m_connection)
            {
                ushort? fileID = m_connection.AllocateFileID();
                if (fileID.HasValue)
                {
                    m_openFiles.Add(fileID.Value, new OpenFileObject(treeID, shareName, relativePath, handle, fileAccess));
                }
                return fileID;
            }
        }

        public OpenFileObject GetOpenFileObject(ushort fileID)
        {
            OpenFileObject openFile;
            m_openFiles.TryGetValue(fileID, out openFile);
            return openFile;
        }

        public void RemoveOpenFile(ushort fileID)
        {
            lock (m_connection)
            {
                m_openFiles.Remove(fileID);
            }
        }

        public List<OpenFileInformation> GetOpenFilesInformation()
        {
            List<OpenFileInformation> result = new List<OpenFileInformation>();
            lock (m_connection)
            {
                foreach (OpenFileObject openFile in m_openFiles.Values)
                {
                    result.Add(new OpenFileInformation(openFile.ShareName, openFile.Path, openFile.FileAccess, openFile.OpenedDT));
                }
            }
            return result;
        }

        private ushort? AllocateSearchHandle()
        {
            for (ushort offset = 0; offset < UInt16.MaxValue; offset++)
            {
                ushort searchHandle = (ushort)(m_nextSearchHandle + offset);
                if (searchHandle == 0 || searchHandle == 0xFFFF)
                {
                    continue;
                }
                if (!m_openSearches.ContainsKey(searchHandle))
                {
                    m_nextSearchHandle = (ushort)(searchHandle + 1);
                    return searchHandle;
                }
            }
            return null;
        }

        public ushort? AddOpenSearch(List<QueryDirectoryFileInformation> entries, int enumerationLocation)
        {
            ushort? searchHandle = AllocateSearchHandle();
            if (searchHandle.HasValue)
            {
                OpenSearch openSearch = new OpenSearch(entries, enumerationLocation);
                m_openSearches.Add(searchHandle.Value, openSearch);
            }
            return searchHandle;
        }

        public OpenSearch GetOpenSearch(ushort searchHandle)
        {
            OpenSearch openSearch;
            m_openSearches.TryGetValue(searchHandle, out openSearch);
            return openSearch;
        }

        public void RemoveOpenSearch(ushort searchHandle)
        {
            m_openSearches.Remove(searchHandle);
        }

        /// <summary>
        /// Free all resources used by this session
        /// </summary>
        public void Close()
        {
            List<ushort> treeIDList = new List<ushort>(m_connectedTrees.Keys);
            foreach (ushort treeID in treeIDList)
            {
                DisconnectTree(treeID);
            }
        }

        public ushort UserID
        {
            get
            {
                return m_userID;
            }
        }

        public SecurityContext SecurityContext
        {
            get
            {
                return m_securityContext;
            }
        }

        public string UserName
        {
            get
            {
                return m_securityContext.UserName;
            }
        }

        public string MachineName
        {
            get
            {
                return m_securityContext.MachineName;
            }
        }

        public DateTime CreationDT
        {
            get
            {
                return m_creationDT;
            }
        }
    }
}