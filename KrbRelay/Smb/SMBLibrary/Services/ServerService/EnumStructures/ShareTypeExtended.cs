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
    /// [MS-SRVS] 2.2.2.4 Share Types
    /// </summary>
    public enum ShareType : uint
    {
        DiskDrive = 0x00000000, // STYPE_DISKTREE
        PrintQueue = 0x00000001, // STYPE_PRINTQ
        CommunicationDevice = 0x00000002, // STYPE_DEVICE
        IPC = 0x00000003, // STYPE_IPC
        ClusterShare = 0x02000000, // STYPE_CLUSTER_FS
        ScaleOutClusterShare = 0x04000000, // STYPE_CLUSTER_SOFS
        DfsShareInCluster = 0x08000000, // STYPE_CLUSTER_DFS
    }

    public struct ShareTypeExtended // uint
    {
        public ShareType ShareType;
        public bool IsSpecial;
        public bool IsTemporary;

        public ShareTypeExtended(ShareType shareType)
        {
            ShareType = shareType;
            IsSpecial = false;
            IsTemporary = false;
        }

        public ShareTypeExtended(ShareType shareType, bool isSpecial, bool isTemporary)
        {
            ShareType = shareType;
            IsSpecial = isSpecial;
            IsTemporary = isTemporary;
        }

        public ShareTypeExtended(NDRParser parser) : this(parser.ReadUInt32())
        {
        }

        public ShareTypeExtended(uint shareTypeExtended)
        {
            ShareType = (ShareType)(shareTypeExtended & 0x0FFFFFFF);
            IsSpecial = (shareTypeExtended & 0x80000000) > 0;
            IsTemporary = (shareTypeExtended & 0x40000000) > 0;
        }

        public void Write(NDRWriter writer)
        {
            writer.WriteUInt32(ToUInt32());
        }

        public uint ToUInt32()
        {
            uint shareTypeExtended = (uint)ShareType;
            if (IsSpecial)
            {
                shareTypeExtended |= 0x80000000;
            }
            if (IsTemporary)
            {
                shareTypeExtended |= 0x40000000;
            }
            return shareTypeExtended;
        }
    }
}