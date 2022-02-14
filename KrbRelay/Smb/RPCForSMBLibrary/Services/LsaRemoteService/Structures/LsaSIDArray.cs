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
    public class LsaSIDArray : INDRStructure
    {
        public List<SID> SIDs;

        public void Read(NDRParser parser)
        {
            throw new NotImplementedException();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32((uint)SIDs.Count);
            if (SIDs != null)
            {
                foreach (SID sid in SIDs)
                {
                    NDRSID ndrSid = new NDRSID(sid);
                    writer.WriteEmbeddedStructureFullPointer(ndrSid);
                }
            }

            writer.EndStructure();
        }
    }
}