/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    public class NDRStatServer : INDRStructure
    {
        public uint sts0_start;
        public uint sts0_fopens;
        public uint sts0_devopens;
        public uint sts0_jobsqueued;
        public uint sts0_sopens;
        public uint sts0_stimedout;
        public uint sts0_serrorout;
        public uint sts0_pwerrors;
        public uint sts0_permerrors;
        public uint sts0_syserrors;
        public uint sts0_bytessent_low;
        public uint sts0_bytessent_high;
        public uint sts0_bytesrcvd_low;
        public uint sts0_bytesrcvd_high;
        public uint sts0_avresponse;
        public uint sts0_reqbufneed;
        public uint sts0_bigbufneed;

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            sts0_start = parser.ReadUInt32();
            sts0_fopens = parser.ReadUInt32();
            sts0_devopens = parser.ReadUInt32();
            sts0_jobsqueued = parser.ReadUInt32();
            sts0_sopens = parser.ReadUInt32();
            sts0_stimedout = parser.ReadUInt32();
            sts0_serrorout = parser.ReadUInt32();
            sts0_pwerrors = parser.ReadUInt32();
            sts0_permerrors = parser.ReadUInt32();
            sts0_syserrors = parser.ReadUInt32();
            sts0_bytessent_low = parser.ReadUInt32();
            sts0_bytessent_high = parser.ReadUInt32();
            sts0_bytesrcvd_low = parser.ReadUInt32();
            sts0_bytesrcvd_high = parser.ReadUInt32();
            sts0_avresponse = parser.ReadUInt32();
            sts0_reqbufneed = parser.ReadUInt32();
            sts0_bigbufneed = parser.ReadUInt32();
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}