/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.Server
{
    internal class SMB1AsyncContext
    {
        public ushort UID; // User ID
        public ushort TID; // Tree ID
        public uint PID; // Process ID
        public ushort MID; // Multiplex ID
        public ushort FileID;
        public SMB1ConnectionState Connection;
        public object IORequest;
    }
}