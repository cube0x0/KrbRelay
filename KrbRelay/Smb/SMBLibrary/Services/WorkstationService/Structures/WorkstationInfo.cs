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
    /// [MS-WKST] WKSTA_INFO Union
    /// </summary>
    public class WorkstationInfo : INDRStructure
    {
        public uint Level;
        public WorkstationInfoLevel Info;

        public WorkstationInfo()
        {
        }

        public WorkstationInfo(uint level)
        {
            Level = level;
        }

        public WorkstationInfo(WorkstationInfoLevel info)
        {
            Level = info.Level;
            Info = info;
        }

        public WorkstationInfo(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            Level = parser.ReadUInt32();
            switch (Level)
            {
                case 100:
                    WorkstationInfo100 info100 = null;
                    parser.ReadEmbeddedStructureFullPointer<WorkstationInfo100>(ref info100);
                    Info = info100;
                    break;

                case 101:
                    WorkstationInfo101 info101 = null;
                    parser.ReadEmbeddedStructureFullPointer<WorkstationInfo101>(ref info101);
                    Info = info101;
                    break;

                default:
                    throw new NotImplementedException();
            }
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            if (Info != null && Level != Info.Level)
            {
                throw new ArgumentException("Invalid WKSTA_INFO Level");
            }

            writer.BeginStructure();
            writer.WriteUInt32(Level);
            writer.WriteEmbeddedStructureFullPointer(Info);
            writer.EndStructure();
        }
    }
}