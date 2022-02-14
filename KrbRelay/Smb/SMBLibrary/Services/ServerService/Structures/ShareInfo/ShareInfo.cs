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
    /// [MS-SRVS] SHARE_INFO Union
    /// </summary>
    public class ShareInfo : INDRStructure
    {
        public uint Level;
        public IShareInfoEntry Info;

        public ShareInfo()
        {
        }

        public ShareInfo(uint level)
        {
            Level = level;
        }

        public ShareInfo(IShareInfoEntry info)
        {
            Level = info.Level;
            Info = info;
        }

        public ShareInfo(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure(); // SHARE_INFO Union
            Level = parser.ReadUInt32();
            switch (Level)
            {
                case 100:
                    ShareInfo0Entry info0 = null;
                    parser.ReadEmbeddedStructureFullPointer<ShareInfo0Entry>(ref info0);
                    Info = info0;
                    break;

                case 101:
                    ShareInfo1Entry info1 = null;
                    parser.ReadEmbeddedStructureFullPointer<ShareInfo1Entry>(ref info1);
                    Info = info1;
                    break;

                default:
                    throw new NotImplementedException();
            }
            parser.EndStructure(); // SHARE_INFO Union
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure(); // SHARE_INFO Union
            writer.WriteUInt32(Level);
            writer.WriteEmbeddedStructureFullPointer(Info);
            writer.EndStructure(); // SHARE_INFO Union
        }
    }
}