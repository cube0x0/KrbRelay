/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SRVS] SHARE_INFO_502
    /// </summary>
    public class ShareInfo502Entry : IShareInfoEntry
    {
        public const uint UnlimitedConnections = 0xFFFFFFFF;

        public NDRUnicodeString NetName;
        public ShareTypeExtended ShareType;
        public NDRUnicodeString Remark;
        public Permissions Permissions; // Windows will leave this field empty (0)
        public uint MaxUses; // Maximum number of concurrent connections that the shared resource can accommodate.
        public uint CurrentUses; // Number of current connections to the resource.
        public NDRUnicodeString Path; // Windows will set this field to the on-disk path (.e.g 'D:\Shared')
        public NDRUnicodeString Password; // Windows will set it to null
        public uint Reserved;
        public SecurityDescriptor securityDescriptor;

        public ShareInfo502Entry()
        {
        }

        public ShareInfo502Entry(string shareName, ShareTypeExtended shareType)
        {
            NetName = new NDRUnicodeString(shareName);
            ShareType = shareType;
            Remark = new NDRUnicodeString(String.Empty);

            MaxUses = UnlimitedConnections;
            Path = new NDRUnicodeString(String.Empty);
            Password = null;

            Reserved = 0;
            securityDescriptor = new SecurityDescriptor();
        }

        public ShareInfo502Entry(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            parser.ReadEmbeddedStructureFullPointer(ref NetName);
            ShareType = new ShareTypeExtended(parser);
            parser.ReadEmbeddedStructureFullPointer(ref Remark);
            Permissions = (Permissions)parser.ReadUInt32();
            MaxUses = parser.ReadUInt32();
            CurrentUses = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref Path);
            parser.ReadEmbeddedStructureFullPointer(ref Password);
            Reserved = parser.ReadUInt32();
            //parser.ReadEmbeddedStructureFullPointer(ref securityDescriptor);
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteEmbeddedStructureFullPointer(NetName);
            ShareType.Write(writer);
            writer.WriteEmbeddedStructureFullPointer(Remark);
            writer.WriteUInt32((uint)Permissions);
            writer.WriteUInt32(MaxUses);
            writer.WriteUInt32(CurrentUses);
            writer.WriteEmbeddedStructureFullPointer(Path);
            writer.WriteEmbeddedStructureFullPointer(Password);
            writer.WriteUInt32(Reserved);
            //writer.WriteStructure(securityDescriptor);
            writer.EndStructure();
        }

        public uint Level
        {
            get
            {
                return 502;
            }
        }
    }
}