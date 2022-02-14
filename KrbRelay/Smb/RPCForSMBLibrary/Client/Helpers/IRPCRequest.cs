namespace SMBLibrary.Client.Helpers
{
    public interface IRPCRequest
    {
        byte[] GetBytes();
    }

    //public class IRPCRequest
    //{
    //    public byte[] GetBytes()
    //    {
    //        NDRWriter writer = new NDRWriter();
    //        return writer.GetBytes();
    //    }
    //}
}