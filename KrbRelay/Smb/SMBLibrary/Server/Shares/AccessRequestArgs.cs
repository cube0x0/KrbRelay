/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using System.Net;

namespace SMBLibrary.Server
{
    public class AccessRequestArgs : EventArgs
    {
        public string UserName;
        public string Path;
        public FileAccess RequestedAccess;
        public string MachineName;
        public IPEndPoint ClientEndPoint;
        public bool Allow = true;

        public AccessRequestArgs(string userName, string path, FileAccess requestedAccess, string machineName, IPEndPoint clientEndPoint)
        {
            UserName = userName;
            Path = path;
            RequestedAccess = requestedAccess;
            MachineName = machineName;
            ClientEndPoint = clientEndPoint;
        }
    }
}