/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// [MS-SRVS] SHARE_ENUM_STRUCT and the embedded SHARE_ENUM_UNION
    /// </summary>
    public class ShareEnum : INDRStructure
    {
        public uint Level;
        public IShareInfoContainer Info;

        public ShareEnum()
        {
        }

        public ShareEnum(uint level)
        {
            Level = level;
        }

        public ShareEnum(IShareInfoContainer info)
        {
            Level = info.Level;
            Info = info;
        }

        public ShareEnum(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure(); // SHARE_ENUM_STRUCT
            Level = parser.ReadUInt32();
            parser.BeginStructure(); // SHARE_ENUM_UNION
            // 14.3.8 - For a non-encapsulated union, the discriminant is marshalled into the transmitted data stream twice.
            // once as the field or parameter, which is referenced by the switch_is construct, in the procedure argument list;
            // and once as the first part of the union representation.
            uint level = parser.ReadUInt32();
            switch (level)
            {
                case 0:
                    ShareInfo0Container info0 = null;
                    parser.ReadEmbeddedStructureFullPointer<ShareInfo0Container>(ref info0);
                    Info = info0;
                    break;

                case 1:
                    ShareInfo1Container info1 = null;
                    parser.ReadEmbeddedStructureFullPointer<ShareInfo1Container>(ref info1);
                    Info = info1;
                    break;

                case 2:
                    ShareInfo2Container info2 = null;
                    parser.ReadEmbeddedStructureFullPointer<ShareInfo2Container>(ref info2);
                    Info = info2;
                    break;

                case 501:
                case 502:
                case 503:
                    throw new NotImplementedException();
                default:
                    break;
            }
            parser.EndStructure(); // SHARE_ENUM_UNION
            parser.EndStructure(); // SHARE_ENUM_STRUCT
        }

        public void Write(NDRWriter writer)
        {
            if (Info != null && Level != Info.Level)
            {
                throw new ArgumentException("SHARE_ENUM_STRUCT Level mismatch");
            }

            writer.BeginStructure(); // SHARE_ENUM_STRUCT
            writer.WriteUInt32(Level);
            writer.BeginStructure(); // SHARE_ENUM_UNION
            writer.WriteUInt32(Level);
            writer.WriteEmbeddedStructureFullPointer(Info);
            writer.EndStructure(); // SHARE_ENUM_UNION
            writer.EndStructure(); // SHARE_ENUM_STRUCT
        }
    }
}