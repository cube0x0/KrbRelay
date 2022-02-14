/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// NDR - Native Data Representation
    /// See DCE 1.1: Remote Procedure Call, Chapter 14 - Transfer Syntax NDR
    /// </summary>
    public class NDRParser
    {
        private byte[] m_buffer;
        private int m_offset;
        private int m_depth;
        private List<INDRStructure> m_deferredStructures = new List<INDRStructure>();
        private Dictionary<uint, INDRStructure> m_referentToInstance = new Dictionary<uint, INDRStructure>();

        public NDRParser(byte[] buffer)
        {
            m_buffer = buffer;
            m_offset = 0;
            m_depth = 0;
        }

        public void BeginStructure()
        {
            m_depth++;
        }

        /// <summary>
        /// Add embedded pointer deferred structure (referent) parser
        /// </summary>
        private void AddDeferredStructure(INDRStructure structure)
        {
            m_deferredStructures.Add(structure);
        }

        public void EndStructure()
        {
            m_depth--;
            // 14.3.12.3 - Algorithm for Deferral of Referents
            // Representations of (embedded) pointer referents are ordered according to a left-to-right, depth-first traversal of the embedding construction.
            // referent representations for the embedded construction are further deferred to a position in the octet stream that
            // follows the representation of the embedding construction. The set of referent representations for the embedded construction
            // is inserted among the referent representations for any pointers in the embedding construction, according to the order of elements or
            // members in the embedding construction
            if (m_depth == 0)
            {
                // Make a copy of all the deferred structures, additional deferred structures will be inserted to m_deferredStructures
                // as we process the existing list
                List<INDRStructure> deferredStructures = new List<INDRStructure>(m_deferredStructures);
                m_deferredStructures.Clear();
                // Read all deferred types:
                foreach (INDRStructure deferredStructure in deferredStructures)
                {
                    deferredStructure.Read(this);
                }
            }
        }

        public string ReadUnicodeString()
        {
            NDRUnicodeString unicodeString = new NDRUnicodeString(this);
            return unicodeString.Value;
        }

        public void ReadStructure(INDRStructure structure)
        {
            structure.Read(this);
        }

        // 14.3.11.1 - Top-level Full Pointers
        public string ReadTopLevelUnicodeStringPointer()
        {
            uint referentID = ReadUInt32();
            if (referentID == 0)
            {
                return null;
            }

            if (m_referentToInstance.ContainsKey(referentID))
            {
                NDRUnicodeString unicodeString = (NDRUnicodeString)m_referentToInstance[referentID];
                return unicodeString.Value;
            }
            else
            {
                NDRUnicodeString unicodeString = new NDRUnicodeString(this);
                m_referentToInstance.Add(referentID, unicodeString);
                return unicodeString.Value;
            }
        }

        public void ReadEmbeddedStructureFullPointer(ref NDRUnicodeString structure)
        {
            ReadEmbeddedStructureFullPointer<NDRUnicodeString>(ref structure);
        }

        public void ReadEmbeddedStructureFullPointer<T>(ref T structure) where T : INDRStructure, new()
        {
            uint referentID = ReadUInt32();
            if (referentID != 0) // not null
            {
                if (structure == null)
                {
                    structure = new T();
                }
                AddDeferredStructure(structure);
            }
            else
            {
                structure = default(T);
            }
        }

        // 14.2.2 - Alignment of Primitive Types
        public uint ReadUInt16()
        {
            m_offset += (2 - (m_offset % 2)) % 2;
            return LittleEndianReader.ReadUInt16(m_buffer, ref m_offset);
        }

        // 14.2.2 - Alignment of Primitive Types
        public uint ReadUInt32()
        {
            m_offset += (4 - (m_offset % 4)) % 4;
            return LittleEndianReader.ReadUInt32(m_buffer, ref m_offset);
        }

        public byte[] ReadBytes(int count)
        {
            return ByteReader.ReadBytes(m_buffer, ref m_offset, count);
        }
    }
}