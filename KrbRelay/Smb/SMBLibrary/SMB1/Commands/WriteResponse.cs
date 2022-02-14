using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_WRITE Response.
    /// This command is obsolete.
    /// Windows NT4 SP6 will send this command with empty data for some reason.
    /// </summary>
    public class WriteResponse : SMB1Command
    {
        public const int ParametersLength = 2;

        // Parameters:
        public ushort CountOfBytesWritten;

        public WriteResponse() : base()
        {
        }

        public WriteResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            CountOfBytesWritten = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, CountOfBytesWritten);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_WRITE;
            }
        }
    }
}