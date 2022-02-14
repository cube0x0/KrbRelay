/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.2.1.1. HEADER
    /// </summary>
    public enum SessionPacketTypeName : byte
    {
        SessionMessage = 0x00,
        SessionRequest = 0x81,
        PositiveSessionResponse = 0x82,
        NegativeSessionResponse = 0x83,
        RetargetSessionResponse = 0x84,
        SessionKeepAlive = 0x85,
    }
}