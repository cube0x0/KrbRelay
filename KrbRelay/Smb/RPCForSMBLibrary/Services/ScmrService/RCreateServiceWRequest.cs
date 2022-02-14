using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// RCreateServiceW   Request (opnum 12)
/// </summary>
public class RCreateServiceWRequest : IRPCRequest
{
    public LPSC_RPC_HANDLE lpScHandle;
    public string lpServiceName;
    public string lpDisplayName;
    public uint dwDesiredAccess;
    public uint dwServiceType;
    public SERIVCE_STARTUP dwStartType;
    public uint dwErrorControl;
    public string lpBinaryPathName;
    public string lpLoadOrderGroup;
    public uint lpdwTagId;
    public string lpDependencies;
    public uint dwDependSize;
    public string lpServiceStartName;
    public string lpPassword;
    public uint dwPwSize;

    public RCreateServiceWRequest()
    {
    }

    public byte[] GetBytes()
    {
        NDRWriter writer = new NDRWriter();
        writer.WriteStructure(lpScHandle);
        writer.WriteUnicodeString(lpServiceName);
        writer.WriteTopLevelUnicodeStringPointer(lpDisplayName);
        writer.WriteUInt32((uint)dwDesiredAccess);
        writer.WriteUInt32((uint)dwServiceType);
        writer.WriteUInt32((uint)dwStartType);
        writer.WriteUInt32((uint)dwErrorControl);
        writer.WriteUnicodeString(lpBinaryPathName);
        writer.WriteTopLevelUnicodeStringPointer(lpLoadOrderGroup);
        writer.WriteUInt32((uint)lpdwTagId);
        writer.WriteTopLevelUnicodeStringPointer(lpDependencies);
        writer.WriteUInt32((uint)dwDependSize);
        writer.WriteTopLevelUnicodeStringPointer(lpServiceStartName);
        writer.WriteTopLevelUnicodeStringPointer(lpPassword);
        writer.WriteUInt32((uint)dwPwSize);
        return writer.GetBytes();
    }
}