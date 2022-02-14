using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// schRpcGetLastRunInfo  Request (opnum 01)
/// </summary>
public class schRpcGetLastRunInfoRequest : IRPCRequest
{
    public SamprHandle SamprHandle;

    public schRpcGetLastRunInfoRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(SamprHandle);
        return writer.GetBytes();
    }
}