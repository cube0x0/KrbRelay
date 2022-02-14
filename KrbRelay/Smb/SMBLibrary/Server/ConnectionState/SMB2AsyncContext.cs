/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB2;

namespace SMBLibrary.Server
{
    internal class SMB2AsyncContext
    {
        public ulong AsyncID;
        public FileID FileID;
        public SMB2ConnectionState Connection;
        public ulong SessionID;
        public uint TreeID;
        public object IORequest;
    }
}