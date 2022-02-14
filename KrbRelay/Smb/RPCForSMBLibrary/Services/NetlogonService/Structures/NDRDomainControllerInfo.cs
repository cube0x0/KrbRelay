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
    public class NDRDomainControllerInfo : INDRStructure
    {
        public NDRUnicodeString DomainControllerName;
        public NDRUnicodeString DomainControllerAddress;
        public uint DomainControllerAddressType;
        public Guid DomainGuid;
        public NDRUnicodeString DomainName;
        public NDRUnicodeString DnsForestName;
        public uint Flags;
        public NDRUnicodeString DcSiteName;
        public NDRUnicodeString ClientSiteName;

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            parser.ReadEmbeddedStructureFullPointer(ref DomainControllerName);
            parser.ReadEmbeddedStructureFullPointer(ref DomainControllerAddress);
            DomainControllerAddressType = parser.ReadUInt32();

            DomainGuid = new Guid(parser.ReadBytes(16));

            parser.ReadEmbeddedStructureFullPointer(ref DomainName);
            parser.ReadEmbeddedStructureFullPointer(ref DnsForestName);

            Flags = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref DcSiteName);
            parser.ReadEmbeddedStructureFullPointer(ref ClientSiteName);

            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}