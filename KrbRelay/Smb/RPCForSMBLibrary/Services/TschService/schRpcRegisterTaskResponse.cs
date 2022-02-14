using SMBLibrary.RPC;
using SMBLibrary.Services;

/// <summary>
/// SchRpcRegisterTask Response (opnum 01)
/// </summary>
public class schRpcRegisterTaskResponse
{
    public string ActualPath;
    public TASK_XML_ERROR_INFO ErrorInfo;

    public schRpcRegisterTaskResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
        ActualPath = parser.ReadUnicodeString();
        ErrorInfo = new TASK_XML_ERROR_INFO();
        parser.ReadStructure(ErrorInfo);
    }
}