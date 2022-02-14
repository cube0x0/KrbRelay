/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;

namespace SMBLibrary.Server
{
    internal class OpenFileObject
    {
        private uint m_treeID;
        private string m_shareName;
        private string m_path;
        private object m_handle;
        private FileAccess m_fileAccess;
        private DateTime m_openedDT;

        public OpenFileObject(uint treeID, string shareName, string path, object handle, FileAccess fileAccess)
        {
            m_treeID = treeID;
            m_shareName = shareName;
            m_path = path;
            m_handle = handle;
            m_fileAccess = fileAccess;
            m_openedDT = DateTime.UtcNow;
        }

        public uint TreeID
        {
            get
            {
                return m_treeID;
            }
        }

        public string ShareName
        {
            get
            {
                return m_shareName;
            }
        }

        public string Path
        {
            get
            {
                return m_path;
            }
            set
            {
                m_path = value;
            }
        }

        public object Handle
        {
            get
            {
                return m_handle;
            }
        }

        public FileAccess FileAccess
        {
            get
            {
                return m_fileAccess;
            }
        }

        public DateTime OpenedDT
        {
            get
            {
                return m_openedDT;
            }
        }
    }
}