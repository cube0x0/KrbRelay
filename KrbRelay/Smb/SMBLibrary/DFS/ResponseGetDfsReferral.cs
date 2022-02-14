/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-DFSC] RESP_GET_DFS_REFERRAL
    /// </summary>
    public class ResponseGetDfsReferral
    {
        public ushort PathConsumed;
        public ushort NumberOfReferrals;
        public uint ReferralHeaderFlags;
        public List<DfsReferralEntry> ReferralEntries;
        public List<string> StringBuffer;
        // Padding

        public ResponseGetDfsReferral()
        {
            throw new NotImplementedException();
        }

        public ResponseGetDfsReferral(byte[] buffer)
        {
            throw new NotImplementedException();
        }

        public byte[] GetBytes()
        {
            throw new NotImplementedException();
        }
    }
}