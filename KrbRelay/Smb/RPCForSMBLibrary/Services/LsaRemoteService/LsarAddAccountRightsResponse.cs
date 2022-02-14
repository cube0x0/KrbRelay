using SMBLibrary.RPC;

/// <summary>
/// LsarAddAccountRights Response (opnum 37)
/// </summary>
public class LsarAddAccountRightsResponse
{
    public LsarAddAccountRightsResponse(byte[] buffer)
    {
        NDRParser parser = new NDRParser(buffer);
    }
}