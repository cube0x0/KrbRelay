/* Copyright (C) 2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using Utilities;

namespace SMBLibrary.Authentication.GSSAPI
{
    /// <summary>
    /// [MS-SPNG] - NegTokenInit2
    /// </summary>
    public class SimpleProtectedNegotiationTokenInit2 : SimpleProtectedNegotiationTokenInit
    {
        public const byte NegHintsTag = 0xA3;
        public new const byte MechanismListMICTag = 0xA4;

        public const byte HintNameTag = 0xA0;
        public const byte HintAddressTag = 0xA1;

        public string HintName;
        public byte[] HintAddress;

        public SimpleProtectedNegotiationTokenInit2()
        {
            HintName = "not_defined_in_RFC4178@please_ignore";
        }

        /// <param name="offset">The offset following the NegTokenInit2 tag</param>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SimpleProtectedNegotiationTokenInit2(byte[] buffer, int offset)
        {
            int constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            byte tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.Sequence)
            {
                throw new InvalidDataException();
            }
            int sequenceLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            int sequenceEndOffset = offset + sequenceLength;
            while (offset < sequenceEndOffset)
            {
                tag = ByteReader.ReadByte(buffer, ref offset);
                if (tag == MechanismTypeListTag)
                {
                    MechanismTypeList = ReadMechanismTypeList(buffer, ref offset);
                }
                else if (tag == RequiredFlagsTag)
                {
                    throw new NotImplementedException("negTokenInit.ReqFlags is not implemented");
                }
                else if (tag == MechanismTokenTag)
                {
                    MechanismToken = ReadMechanismToken(buffer, ref offset);
                }
                else if (tag == NegHintsTag)
                {
                    HintName = ReadHints(buffer, ref offset, out HintAddress);
                }
                else if (tag == MechanismListMICTag)
                {
                    MechanismListMIC = ReadMechanismListMIC(buffer, ref offset);
                }
                else
                {
                    throw new InvalidDataException("Invalid negTokenInit structure");
                }
            }
        }

        public override byte[] GetBytes()
        {
            int sequenceLength = GetTokenFieldsLength();
            int sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
            int constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
            int constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
            int bufferSize = 1 + constructionLengthFieldSize + 1 + sequenceLengthFieldSize + sequenceLength;
            byte[] buffer = new byte[bufferSize];
            int offset = 0;
            ByteWriter.WriteByte(buffer, ref offset, NegTokenInitTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.Sequence);
            DerEncodingHelper.WriteLength(buffer, ref offset, sequenceLength);
            if (MechanismTypeList != null)
            {
                WriteMechanismTypeList(buffer, ref offset, MechanismTypeList);
            }
            if (MechanismToken != null)
            {
                WriteMechanismToken(buffer, ref offset, MechanismToken);
            }
            if (HintName != null || HintAddress != null)
            {
                WriteHints(buffer, ref offset, HintName, HintAddress);
            }
            if (MechanismListMIC != null)
            {
                WriteMechanismListMIC(buffer, ref offset, MechanismListMIC);
            }
            return buffer;
        }

        protected override int GetTokenFieldsLength()
        {
            int result = base.GetTokenFieldsLength(); ;
            if (HintName != null || HintAddress != null)
            {
                int hintsSequenceLength = GetHintsSequenceLength(HintName, HintAddress);
                int hintsSequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintsSequenceLength);
                int hintsSequenceConstructionLength = 1 + hintsSequenceLengthFieldSize + hintsSequenceLength;
                int hintsSequenceConstructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintsSequenceConstructionLength);
                int entryLength = 1 + hintsSequenceConstructionLengthFieldSize + 1 + hintsSequenceLengthFieldSize + hintsSequenceLength;
                result += entryLength;
            }
            return result;
        }

        protected static string ReadHints(byte[] buffer, ref int offset, out byte[] hintAddress)
        {
            string hintName = null;
            hintAddress = null;
            int constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            byte tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.Sequence)
            {
                throw new InvalidDataException();
            }
            int sequenceLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            int sequenceEndOffset = offset + sequenceLength;
            while (offset < sequenceEndOffset)
            {
                tag = ByteReader.ReadByte(buffer, ref offset);
                if (tag == HintNameTag)
                {
                    hintName = ReadHintName(buffer, ref offset);
                }
                else if (tag == HintAddressTag)
                {
                    hintAddress = ReadHintAddress(buffer, ref offset);
                }
                else
                {
                    throw new InvalidDataException();
                }
            }
            return hintName;
        }

        protected static string ReadHintName(byte[] buffer, ref int offset)
        {
            int constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            byte tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.GeneralString)
            {
                throw new InvalidDataException();
            }
            int hintLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            byte[] hintNameBytes = ByteReader.ReadBytes(buffer, ref offset, hintLength);
            return DerEncodingHelper.DecodeGeneralString(hintNameBytes);
        }

        protected static byte[] ReadHintAddress(byte[] buffer, ref int offset)
        {
            int constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            byte tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.ByteArray)
            {
                throw new InvalidDataException();
            }
            int hintLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            return ByteReader.ReadBytes(buffer, ref offset, hintLength);
        }

        protected static int GetHintsSequenceLength(string hintName, byte[] hintAddress)
        {
            int sequenceLength = 0;
            if (hintName != null)
            {
                byte[] hintNameBytes = DerEncodingHelper.EncodeGeneralString(hintName);
                int lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintNameBytes.Length);
                int constructionLength = 1 + lengthFieldSize + hintNameBytes.Length;
                int constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
                int entryLength = 1 + constructionLengthFieldSize + 1 + lengthFieldSize + hintNameBytes.Length;
                sequenceLength += entryLength;
            }
            if (hintAddress != null)
            {
                int lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintAddress.Length);
                int constructionLength = 1 + lengthFieldSize + hintAddress.Length;
                int constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
                int entryLength = 1 + constructionLengthFieldSize + 1 + lengthFieldSize + hintAddress.Length;
                sequenceLength += entryLength;
            }
            return sequenceLength;
        }

        private static void WriteHints(byte[] buffer, ref int offset, string hintName, byte[] hintAddress)
        {
            int sequenceLength = GetHintsSequenceLength(hintName, hintAddress);
            int sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
            int constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
            ByteWriter.WriteByte(buffer, ref offset, NegHintsTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.Sequence);
            DerEncodingHelper.WriteLength(buffer, ref offset, sequenceLength);
            if (hintName != null)
            {
                WriteHintName(buffer, ref offset, hintName);
            }
            if (hintAddress != null)
            {
                WriteHintAddress(buffer, ref offset, hintAddress);
            }
        }

        private static void WriteHintName(byte[] buffer, ref int offset, string hintName)
        {
            byte[] hintNameBytes = DerEncodingHelper.EncodeGeneralString(hintName);
            int constructionLength = 1 + DerEncodingHelper.GetLengthFieldSize(hintNameBytes.Length) + hintNameBytes.Length;
            ByteWriter.WriteByte(buffer, ref offset, HintNameTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.GeneralString);
            DerEncodingHelper.WriteLength(buffer, ref offset, hintNameBytes.Length);
            ByteWriter.WriteBytes(buffer, ref offset, hintNameBytes);
        }

        private static void WriteHintAddress(byte[] buffer, ref int offset, byte[] hintAddress)
        {
            int constructionLength = 1 + DerEncodingHelper.GetLengthFieldSize(hintAddress.Length) + hintAddress.Length;
            ByteWriter.WriteByte(buffer, ref offset, HintAddressTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, hintAddress.Length);
            ByteWriter.WriteBytes(buffer, ref offset, hintAddress);
        }

        protected new static void WriteMechanismListMIC(byte[] buffer, ref int offset, byte[] mechanismListMIC)
        {
            int mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismListMIC.Length);
            ByteWriter.WriteByte(buffer, ref offset, MechanismListMICTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, 1 + mechanismListMICLengthFieldSize + mechanismListMIC.Length);
            ByteWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, mechanismListMIC.Length);
            ByteWriter.WriteBytes(buffer, ref offset, mechanismListMIC);
        }
    }
}