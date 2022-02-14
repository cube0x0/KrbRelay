using SMBLibrary;
using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;

/// <summary>
/// SamrConnect  Request (opnum 0)
/// </summary>
public class SamrConnectRequest : IRPCRequest
{
    public AccessMask DesiredAccess;

    public SamrConnectRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteTopLevelUnicodeStringPointer(null);
        writer.WriteUInt32((uint)DesiredAccess);
        return writer.GetBytes();
    }
}