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
    /// [MS-SRVS] SERVER_INFO Union
    /// </summary>
    public class ServerInfo : INDRStructure
    {
        public uint Level;
        public ServerInfoLevel Info;

        public ServerInfo()
        {
        }

        public ServerInfo(uint level)
        {
            Level = level;
        }

        public ServerInfo(ServerInfoLevel info)
        {
            Level = info.Level;
            Info = info;
        }

        public ServerInfo(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure(); // SERVER_INFO Union
            Level = parser.ReadUInt32();
            switch (Level)
            {
                case 100:
                    ServerInfo100 info100 = null;
                    parser.ReadEmbeddedStructureFullPointer<ServerInfo100>(ref info100);
                    Info = info100;
                    break;

                case 101:
                    ServerInfo101 info101 = null;
                    parser.ReadEmbeddedStructureFullPointer<ServerInfo101>(ref info101);
                    Info = info101;
                    break;

                default:
                    throw new NotImplementedException();
            }
            ;
            parser.EndStructure(); // SERVER_INFO Union
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure(); // SERVER_INFO Union
            writer.WriteUInt32(Level);
            writer.WriteEmbeddedStructureFullPointer(Info);
            writer.EndStructure(); // SERVER_INFO Union
        }
    }
}