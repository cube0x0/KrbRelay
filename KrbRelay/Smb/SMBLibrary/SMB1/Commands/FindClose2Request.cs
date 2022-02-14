using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_FIND_CLOSE2 Request
    /// </summary>
    public class FindClose2Request : SMB1Command
    {
        public const int ParameterCount = 2;

        // Parameters:
        public ushort SearchHandle;

        public FindClose2Request() : base()
        {
        }

        public FindClose2Request(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            SearchHandle = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_FIND_CLOSE2;
            }
        }
    }
}