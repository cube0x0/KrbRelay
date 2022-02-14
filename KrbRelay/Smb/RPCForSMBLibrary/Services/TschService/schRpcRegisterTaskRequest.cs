using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// SchRpcRegisterTask  Request (opnum 01)
/// </summary>
public class schRpcRegisterTaskRequest : IRPCRequest
{
    public string path;
    public string xml;
    public TASK_CREATION flags;
    public string sddl;
    public TASK_LOGON_TYPE logonType;
    public uint cCreds;
    public TASK_USER_CRED pCreds;

    public schRpcRegisterTaskRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteTopLevelUnicodeStringPointer(path);
        writer.WriteTopLevelUnicodeStringPointer(xml);
        writer.WriteUInt32((uint)flags);
        writer.WriteTopLevelUnicodeStringPointer(sddl);
        writer.WriteUInt32((uint)logonType);
        writer.WriteUInt32(cCreds);
        writer.WriteStructure(pCreds);
        return writer.GetBytes();
    }
}