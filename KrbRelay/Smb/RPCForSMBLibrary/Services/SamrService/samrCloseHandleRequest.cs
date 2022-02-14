using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// samrCloseHandle  Request (opnum 01)
/// </summary>
public class samrCloseHandleRequest : IRPCRequest
{
    public SamprHandle SamprHandle;

    public samrCloseHandleRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(SamprHandle);
        return writer.GetBytes();
    }
}