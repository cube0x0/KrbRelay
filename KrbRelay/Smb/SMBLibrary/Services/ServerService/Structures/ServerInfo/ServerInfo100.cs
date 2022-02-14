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
    /// [MS-SRVS] SERVER_INFO_100
    /// </summary>
    public class ServerInfo100 : ServerInfoLevel
    {
        public PlatformName PlatformID;
        public NDRUnicodeString ServerName;

        public ServerInfo100()
        {
            ServerName = new NDRUnicodeString();
        }

        public ServerInfo100(NDRParser parser)
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
            parser.EndStructure();
        }

        public override void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32((uint)PlatformID);
            writer.WriteEmbeddedStructureFullPointer(ServerName);
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