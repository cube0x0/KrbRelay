namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_FIND_CLOSE2 Response
    /// </summary>
    public class FindClose2Response : SMB1Command
    {
        public FindClose2Response() : base()
        {
        }

        public FindClose2Response(byte[] buffer, int offset) : base(buffer, offset, false)
        {
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