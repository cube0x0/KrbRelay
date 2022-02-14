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
    /// [MS-SRVS] SHARE_INFO_2_CONTAINER
    /// </summary>
    public class ShareInfo2Container : IShareInfoContainer
    {
        public NDRConformantArray<ShareInfo2Entry> Entries;

        public ShareInfo2Container()
        {
        }

        public ShareInfo2Container(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            uint count = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer<NDRConformantArray<ShareInfo2Entry>>(ref Entries);
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32((uint)this.Count);
            writer.WriteEmbeddedStructureFullPointer(Entries);
            writer.EndStructure();
        }

        public uint Level
        {
            get
            {
                return 2;
            }
        }

        public int Count
        {
            get
            {
                if (Entries != null)
                {
                    return Entries.Count;
                }
                else
                {
                    return 0;
                }
            }
        }

        public void Add(ShareInfo2Entry entry)
        {
            if (Entries == null)
            {
                Entries = new NDRConformantArray<ShareInfo2Entry>();
            }
            Entries.Add(entry);
        }
    }
}