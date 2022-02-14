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
    /// [MS-SRVS] SERVER_INFO_101
    /// </summary>
    public class ServerInfo101 : ServerInfoLevel
    {
        public PlatformName PlatformID;
        public NDRUnicodeString ServerName;
        public uint VerMajor;
        public uint VerMinor;
        public ServerType Type;
        public NDRUnicodeString Comment;

        public ServerInfo101()
        {
            ServerName = new NDRUnicodeString();
            Comment = new NDRUnicodeString();
        }

        public ServerInfo101(NDRParser parser)
        {
            Read(parser);
        }

        public override void Read(NDRParser parser)
        {
            // If an array, structure, or union embeds a pointer, the representation of the referent of the
            // pointer is deferred to a position in the octet stream that follows the representation of the
            // embedding construction
            parser.BeginStructure();
            PlatformID = (PlatformName)parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref ServerName);
            VerMajor = parser.ReadUInt32();
            VerMinor = parser.ReadUInt32();
            Type = (ServerType)parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref Comment);
            parser.EndStructure();
        }

        public override void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32((uint)PlatformID);
            writer.WriteEmbeddedStructureFullPointer(ServerName);
            writer.WriteUInt32(VerMajor);
            writer.WriteUInt32(VerMinor);
            writer.WriteUInt32((uint)Type);
            writer.WriteEmbeddedStructureFullPointer(Comment);
            writer.EndStructure();
        }

        /*
        public static ServerInfo101 ReadServerInfo101Pointer(NDRParser parser)
        {
            uint referentID = parser.ReadUInt32(); // ServerInfoLevel pointer
            ServerInfo101 info = new ServerInfo101(parser);
            parser.AddReferentInstance(referentID, info);
            return info;
        }*/

        public override uint Level
        {
            get
            {
                return 101;
            }
        }
    }
}