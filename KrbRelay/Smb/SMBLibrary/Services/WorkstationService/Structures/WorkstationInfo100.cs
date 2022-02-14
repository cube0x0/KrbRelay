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
    /// [MS-WKST] WKSTA_INFO_100
    /// </summary>
    public class WorkstationInfo100 : WorkstationInfoLevel
    {
        public uint PlatformID;
        public NDRUnicodeString ComputerName;
        public NDRUnicodeString LanGroup;
        public uint VerMajor;
        public uint VerMinor;

        public WorkstationInfo100()
        {
            ComputerName = new NDRUnicodeString();
            LanGroup = new NDRUnicodeString();
        }

        public WorkstationInfo100(NDRParser parser)
        {
            Read(parser);
        }

        public override void Read(NDRParser parser)
        {
            // If an array, structure, or union embeds a pointer, the representation of the referent of the
            // pointer is deferred to a position in the octet stream that follows the representation of the
            // embedding construction
            parser.BeginStructure();
            PlatformID = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref ComputerName);
            parser.ReadEmbeddedStructureFullPointer(ref LanGroup);
            VerMajor = parser.ReadUInt32();
            VerMinor = parser.ReadUInt32();
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
            writer.EndStructure();
        }

        public override uint Level
        {
            get
            {
                return 100;
            }
        }
    }
}