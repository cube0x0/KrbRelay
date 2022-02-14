/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using System;
using System.Collections.Generic;

namespace SMBLibrary.Services
{
    public class LsaUnicodeStringArray : INDRStructure
    {
        public List<LsaUnicodeString> UnicodeStrings;

        public void Read(NDRParser parser)
        {
            throw new NotImplementedException();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32((uint)UnicodeStrings.Count);
            if (UnicodeStrings != null)
            {
                foreach (LsaUnicodeString i in UnicodeStrings)
                {
                    NDRUnicodeString ndrSid = new NDRUnicodeString(i.Value);
                    writer.WriteEmbeddedStructureFullPointer(ndrSid);
                }
            }

            writer.EndStructure();
        }
    }
}