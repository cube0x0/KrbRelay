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
    /// [MS-WKST] WKSTA_INFO_101
    /// </summary>
    public class WorkstationInfo101 : WorkstationInfoLevel
    {
        public uint PlatformID;
        public NDRUnicodeString ComputerName;
        public NDRUnicodeString LanGroup;
        public uint VerMajor;
        public uint VerMinor;
        public NDRUnicodeString LanRoot;

        public WorkstationInfo101()
        {
            ComputerName = new NDRUnicodeString();
            LanGroup = new NDRUnicodeString();
            LanRoot = new NDRUnicodeString();
        }

        public WorkstationInfo101(NDRParser parser)
        {
            Read(parser);
        }

        public override void Read(NDRParser parser)
        {
            parser.BeginStructure();
            PlatformID = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref ComputerName);
            parser.ReadEmbeddedStructureFullPointer(ref LanGroup);
            VerMajor = parser.ReadUInt32();
            VerMinor = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref LanRoot);
            parser.EndStructure();
        }

        public override void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32(PlatformID);
            writer.WriteEmbeddedStructureFullPointer(ComputerName);
            writer.WriteEmbeddedStructureFullPointer(LanGroup);
            writer.WriteUInt32(VerMajor);
            writer.WriteUInt32(VerMinor);
            writer.WriteEmbeddedStructureFullPointer(LanRoot);
            writer.EndStructure();
        }

        public override uint Level
        {
            get
            {
                return 101;
            }
        }
    }
}