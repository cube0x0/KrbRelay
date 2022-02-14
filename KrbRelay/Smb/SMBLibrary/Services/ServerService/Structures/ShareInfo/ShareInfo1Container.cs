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
    /// [MS-SRVS] SHARE_INFO_1_CONTAINER
    /// </summary>
    public class ShareInfo1Container : IShareInfoContainer
    {
        public NDRConformantArray<ShareInfo1Entry> Entries;

        public ShareInfo1Container()
        {
        }

        public ShareInfo1Container(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            uint count = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer<NDRConformantArray<ShareInfo1Entry>>(ref Entries);
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
                return 1;
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

        public void Add(ShareInfo1Entry entry)
        {
            if (Entries == null)
            {
                Entries = new NDRConformantArray<ShareInfo1Entry>();
            }
            Entries.Add(entry);
        }
    }
}