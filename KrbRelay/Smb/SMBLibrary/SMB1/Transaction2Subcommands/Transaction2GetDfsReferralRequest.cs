/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS2_GET_DFS_REFERRAL Request
    /// </summary>
    public class Transaction2GetDfsReferralRequest : Transaction2Subcommand
    {
        // Parameters:
        public RequestGetDfsReferral ReferralRequest;

        public Transaction2GetDfsReferralRequest() : base()
        {
        }

        public Transaction2GetDfsReferralRequest(byte[] parameters, byte[] data) : base()
        {
            ReferralRequest = new RequestGetDfsReferral(parameters);
        }

        public override byte[] GetSetup()
        {
            return LittleEndianConverter.GetBytes((ushort)SubcommandName);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            return ReferralRequest.GetBytes();
        }

        public override Transaction2SubcommandName SubcommandName
        {
            get
            {
                return Transaction2SubcommandName.TRANS2_GET_DFS_REFERRAL;
            }
        }
    }
}