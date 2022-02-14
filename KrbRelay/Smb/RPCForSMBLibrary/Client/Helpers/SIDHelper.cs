/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Text;

namespace SMBLibrary.Client.Helpers
{
    public class SIDHelper
    {
        public static SID CreateFromString(string sidString)
        {
            if (!sidString.StartsWith("S-", StringComparison.InvariantCultureIgnoreCase))
                throw new ApplicationException("The SID " + sidString + " does not start with S-");
            string[] s = sidString.Split('-');
            if (s.Length < 4)
                throw new ApplicationException("The SID " + sidString + " cannot be splitted in subauthorities");

            SID sid = new SID();
            sid.Revision = (byte)int.Parse(s[1]);
            if (int.Parse(s[2]) != 5)
                throw new ApplicationException("The SID " + sidString + " has an unsupported Authority (<> 5)");
            sid.IdentifierAuthority = SID.SECURITY_NT_AUTHORITY;
            for (int i = 3; i < s.Length; i++)
            {
                sid.SubAuthority.Add(uint.Parse(s[i]));
            }
            return sid;
        }

        public static string ToString(SID sid)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("S-");
            sb.Append(sid.Revision);
            sb.Append("-");
            sb.Append(sid.IdentifierAuthority[sid.IdentifierAuthority.Length - 1]);
            foreach (uint subA in sid.SubAuthority)
            {
                sb.Append("-");
                sb.Append(subA);
            }
            return sb.ToString();
        }
    }
}