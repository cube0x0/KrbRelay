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
    /// [MS-SRVS] SHARE_INFO_0_CONTAINER
    /// </summary>
    public class ShareInfo0Container : IShareInfoContainer
    {
        public NDRConformantArray<ShareInfo0Entry> Entries;

        public ShareInfo0Container()
        {
        }

        public ShareInfo0Container(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            uint count = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer<NDRConformantArray<ShareInfo0Entry>>(ref Entries);
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
                return 0;
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

        public void Add(ShareInfo0Entry entry)
        {
            if (Entries == null)
            {
                Entries = new NDRConformantArray<ShareInfo0Entry>();
            }
            Entries.Add(entry);
        }
    }
}