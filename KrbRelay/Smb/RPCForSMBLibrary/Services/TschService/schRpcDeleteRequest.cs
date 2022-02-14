using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// schRpcDelete  Request (opnum 13)
/// </summary>
public class schRpcDeleteRequest : IRPCRequest
{
    public SamprHandle SamprHandle;

    public schRpcDeleteRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(SamprHandle);
        return writer.GetBytes();
    }
}