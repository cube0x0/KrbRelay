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
    public class LsaObjectAttributes : INDRStructure
    {
        // structure not used on the wire, so no need to add encoding extra logic
        public uint Length;

        public string RootDirectory;
        public string ObjectName;
        public uint Attributes;
        public SecurityDescriptor SecurityDescriptor;
        public uint SecurityQualityOfService;

        public void Read(NDRParser parser)
        {
            throw new NotImplementedException();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32(Length);
            writer.WriteUInt32(0);
            writer.WriteUInt32(0);
            writer.WriteUInt32(Attributes);
            writer.WriteUInt32(0);
            writer.WriteUInt32(0);
            writer.EndStructure();
        }
    }
}