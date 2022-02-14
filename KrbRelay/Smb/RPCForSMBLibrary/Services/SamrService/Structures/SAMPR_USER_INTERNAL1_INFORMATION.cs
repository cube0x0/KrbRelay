using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    public class SAMPR_USER_INTERNAL1_INFORMATION : INDRStructure
    {
        public byte[] EncryptedNtOwfPassword;
        public byte[] EncryptedLmOwfPassword;
        public byte NtPasswordPresent;
        public byte LmPasswordPresent;
        public byte PasswordExpired;

        public void Read(NDRParser parser)
        {
            throw new NotImplementedException();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteBytes(EncryptedNtOwfPassword);
            if (EncryptedLmOwfPassword == null)
                writer.WriteBytes(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            else
                writer.WriteBytes(EncryptedLmOwfPassword);
            writer.WriteUInt16(NtPasswordPresent);
            writer.WriteUInt16(LmPasswordPresent);
            writer.WriteUInt16(PasswordExpired);
            writer.EndStructure();
        }
    }
}