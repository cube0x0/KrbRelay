/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Net;

namespace SMBLibrary.Server
{
    public class SessionInformation
    {
        public IPEndPoint ClientEndPoint;
        public SMBDialect Dialect;
        public string UserName;
        public string MachineName;
        public List<OpenFileInformation> OpenFiles;
        public DateTime CreationDT;

        public SessionInformation(IPEndPoint clientEndPoint, SMBDialect dialect, string userName, string machineName, List<OpenFileInformation> openFiles, DateTime creationDT)
        {
            ClientEndPoint = clientEndPoint;
            Dialect = dialect;
            UserName = userName;
            MachineName = machineName;
            OpenFiles = openFiles;
            CreationDT = creationDT;
        }
    }
}