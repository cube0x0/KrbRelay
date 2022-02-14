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
    public class LsaTrustInformation : INDRStructure
    {
        private LsaUnicodeString unicode_string = new LsaUnicodeString();
        public SID Sid;

        public string Name
        {
            get
            {
                return unicode_string.Value;
            }
            set
            {
                unicode_string.Value = value;
            }
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            parser.ReadStructure(unicode_string);
            Sid = new SID();
            NDRSID NDRSid = new NDRSID(Sid);
            parser.ReadEmbeddedStructureFullPointer(ref NDRSid);
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}