/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Services;
using System.Collections.Generic;
using System.Net;

namespace SMBLibrary.Client
{
    public interface ISMBClient
    {
        bool Connect(string serverName, SMBTransportType transport);

        bool Connect(IPAddress serverAddress, SMBTransportType transport);

        void Disconnect();

        byte[] Login(byte[] ticket, out bool successful);

        NTStatus Logoff();

        List<ShareInfo2Entry> ListShares(out NTStatus status);

        ISMBFileStore TreeConnect(string shareName, out NTStatus status);

        uint MaxReadSize
        {
            get;
        }

        uint MaxWriteSize
        {
            get;
        }
    }
}