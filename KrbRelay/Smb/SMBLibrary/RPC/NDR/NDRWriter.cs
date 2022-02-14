/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.IO;
using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// NDR - Native Data Representation
    /// See DCE 1.1: Remote Procedure Call, Chapter 14 - Transfer Syntax NDR
    /// </summary>
    public class NDRWriter
    {
        private MemoryStream m_stream = new MemoryStream();
        private int m_depth;
        private List<INDRStructure> m_deferredStructures = new List<INDRStructure>();
        private Dictionary<uint, INDRStructure> m_referentToInstance = new Dictionary<uint, INDRStructure>();
        private uint m_nextReferentID = 0x00020000;

        public void BeginStructure()
        {
            m_depth++;
        }

        /// <summary>
        /// Add embedded pointer deferred structure (referent) writer
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
                // Write all deferred types:
                foreach (INDRStructure deferredStructure in deferredStructures)
                {
                    deferredStructure.Write(this);
                }
            }
        }

        public void WriteUnicodeString(string value)
        {
            NDRUnicodeString unicodeString = new NDRUnicodeString(value);
            unicodeString.Write(this);
        }

        public void WriteStructure(INDRStructure structure)
        {
            structure.Write(this);
        }

        public void WriteTopLevelUnicodeStringPointer(string value)
        {
            if (value == null)
            {
                WriteUInt32(0);
                return;
            }

            // Note: We do not bother searching for existing values
            uint referentID = GetNextReferentID();
            WriteUInt32(referentID);
            NDRUnicodeString unicodeString = new NDRUnicodeString(value);
            unicodeString.Write(this);
            m_referentToInstance.Add(referentID, unicodeString);
        }

        // 14.3.12.1 Embedded Full Pointers
        public void WriteEmbeddedStructureFullPointer(INDRStructure structure)
        {
            if (structure == null)
            {
                WriteUInt32(0); // null
                return;
            }
            else
            {
                // Note: We do not bother searching for existing values
                uint referentID = GetNextReferentID();
                WriteUInt32(referentID);
                AddDeferredStructure(structure);
                m_referentToInstance.Add(referentID, structure);
            }
        }

        // 14.2.2 - Alignment of Primitive Types
        public void WriteUInt16(ushort value)
        {
            uint padding = (uint)(2 - (m_stream.Position % 2)) % 2;
            m_stream.Position += padding;
            LittleEndianWriter.WriteUInt16(m_stream, value);
        }

        // 14.2.2 - Alignment of Primitive Types
        public void WriteUInt32(uint value)
        {
            uint padding = (uint)(4 - (m_stream.Position % 4)) % 4;
            m_stream.Position += padding;
            LittleEndianWriter.WriteUInt32(m_stream, value);
        }

        public void WriteBytes(byte[] value)
        {
            ByteWriter.WriteBytes(m_stream, value);
        }

        //public void WriteByte(byte value)
        //{
        //    ByteWriter.WriteBytes(m_stream, value);
        //}

        public byte[] GetBytes()
        {
            byte[] buffer = new byte[m_stream.Length];
            m_stream.Seek(0, SeekOrigin.Begin);
            m_stream.Read(buffer, 0, buffer.Length);
            return buffer;
        }

        private uint GetNextReferentID()
        {
            uint result = m_nextReferentID;
            m_nextReferentID++;
            return result;
        }
    }
}