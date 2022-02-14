using SMBLibrary;
using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// LsarAddAccountRights Request (opnum 37)
/// </summary>
public class LsarAddAccountRightsRequest : IRPCRequest
{
    public LsaHandle handle;
    public SID AccountSid;
    public _LSAPR_USER_RIGHT_SET UserRights;

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(handle);
        writer.WriteStructure(new NDRSID(AccountSid));
        writer.WriteStructure(UserRights);

        return writer.GetBytes();
    }
}