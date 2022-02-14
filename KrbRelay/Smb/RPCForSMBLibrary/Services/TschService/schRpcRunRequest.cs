using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// schRpcRun  Request (opnum 01)
/// </summary>
public class schRpcRunRequest : IRPCRequest
{
    public SamprHandle SamprHandle;

    public schRpcRunRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(SamprHandle);
        return writer.GetBytes();
    }
}