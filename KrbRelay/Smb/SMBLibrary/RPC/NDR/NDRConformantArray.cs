/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace SMBLibrary.RPC
{
    public class NDRConformantArray<T> : List<T>, INDRStructure where T : INDRStructure, new()
    {
        /// <summary>
        /// See DCE 1.1: Remote Procedure Call - 14.3.3.2 - Uni-dimensional Conformant Arrays
        /// </summary>
        /// <param name="parser"></param>
        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            uint maxCount = parser.ReadUInt32();
            for (int index = 0; index < maxCount; index++)
            {
                T entry = new T();
                entry.Read(parser);
                this.Add(entry);
            }

            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            uint maxCount = (uint)this.Count;
            writer.WriteUInt32(maxCount);
            for (int index = 0; index < this.Count; index++)
            {
                this[index].Write(writer);
            }
            writer.EndStructure();
        }
    }
}