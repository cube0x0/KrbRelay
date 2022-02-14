/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SRVS] SHARE_INFO_0
    /// </summary>
    public class ShareInfo0Entry : IShareInfoEntry
    {
        public NDRUnicodeString NetName;

        public ShareInfo0Entry()
        {
        }

        public ShareInfo0Entry(string shareName)
        {
            NetName = new NDRUnicodeString(shareName);
        }

        public ShareInfo0Entry(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            parser.ReadEmbeddedStructureFullPointer(ref NetName);
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteEmbeddedStructureFullPointer(NetName);
            writer.EndStructure();
        }

        public uint Level
        {
            get
            {
                return 0;
            }
        }
    }
}