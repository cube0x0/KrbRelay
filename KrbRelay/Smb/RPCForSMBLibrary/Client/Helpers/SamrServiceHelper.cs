using SMBLibrary.Client.Helpers;
using SMBLibrary.RPC;
using SMBLibrary.Services;

namespace SMBLibrary.Client
{
    public class SamrServiceHelper
    {
        public static SamprHandle samrConnect(RPCCallHelper rpc, AccessMask desiredAccess, out NTStatus status)
        {
            SamrConnectRequest samrConnectRequest = new SamrConnectRequest();
            samrConnectRequest.DesiredAccess = desiredAccess;

            SamrConnectResponse samrConnectResponse;

            status = rpc.ExecuteCall((ushort)SamrServiceOpName.SamrConnect, samrConnectRequest, out samrConnectResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return samrConnectResponse.SamrHandle;
        }

        public static samrEnumerateDomainsInSamServerResponse samrEnumerateDomainsInSamServer(RPCCallHelper rpc, SamprHandle ServerHandle, uint EnumerationContext, uint PreferedMaximumLength, out NTStatus status)
        {
            samrEnumerateDomainsInSamServerRequest samrEnumerateDomainsInSamServerRequest = new samrEnumerateDomainsInSamServerRequest();
            samrEnumerateDomainsInSamServerRequest.ServerHandle = ServerHandle;
            samrEnumerateDomainsInSamServerRequest.EnumerationContext = EnumerationContext;
            samrEnumerateDomainsInSamServerRequest.PreferedMaximumLength = PreferedMaximumLength;

            samrEnumerateDomainsInSamServerResponse samrEnumerateDomainsInSamServerResponse;

            status = rpc.ExecuteCall((ushort)SamrServiceOpName.samrEnumerateDomainsInSamServer, samrEnumerateDomainsInSamServerRequest, out samrEnumerateDomainsInSamServerResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return samrEnumerateDomainsInSamServerResponse;
        }

        public static uint samrLookupDomainInSamServer(RPCCallHelper rpc, SamprHandle ServerHandle, string name, out NTStatus status)
        {
            samrLookupDomainInSamServerRequest samrLookupDomainInSamServerRequest = new samrLookupDomainInSamServerRequest();
            samrLookupDomainInSamServerRequest.ServerHandle = ServerHandle;
            samrLookupDomainInSamServerRequest.Name = new NDRUnicodeString(name);

            samrLookupDomainInSamServerResponse samrLookupDomainInSamServerResponse;

            status = rpc.ExecuteCall((ushort)SamrServiceOpName.SamrLookupDomainInSamServer, samrLookupDomainInSamServerRequest, out samrLookupDomainInSamServerResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return 0;
            }
            return samrLookupDomainInSamServerResponse.DomainId;
        }

        public static SamprHandle samrOpenDomain(RPCCallHelper rpc, SamprHandle ServerHandle, AccessMask desiredAccess, SID sid, out NTStatus status)
        {
            samrOpenDomainRequest samrOpenDomainRequest = new samrOpenDomainRequest();
            samrOpenDomainRequest.SamprHandle = ServerHandle;
            samrOpenDomainRequest.DesiredAccess = desiredAccess;
            samrOpenDomainRequest.DomainId = sid;

            samrOpenDomainResponse samrOpenDomainResponse;

            status = rpc.ExecuteCall((ushort)SamrServiceOpName.SamrOpenDomain, samrOpenDomainRequest, out samrOpenDomainResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return samrOpenDomainResponse.DomainHandle;
        }

        public static SamprHandle samrOpenGroup(RPCCallHelper rpc, SamprHandle domainHandle, AccessMask desiredAccess, uint rid, out NTStatus status)
        {
            samrOpenGroupRequest samrOpenGroupRequest = new samrOpenGroupRequest();
            samrOpenGroupRequest.DomainHandle = domainHandle;
            samrOpenGroupRequest.DesiredAccess = desiredAccess;
            samrOpenGroupRequest.GroupId = rid;

            samrOpenGroupResponse samrOpenGroupResponse;

            status = rpc.ExecuteCall((ushort)SamrServiceOpName.samrOpenGroup, samrOpenGroupRequest, out samrOpenGroupResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return samrOpenGroupResponse.GroupHandle;
        }

        public static SamprHandle samrOpenUser(RPCCallHelper rpc, SamprHandle domainHandle, AccessMask desiredAccess, uint rid, out NTStatus status)
        {
            samrOpenUserRequest samrOpenUserRequest = new samrOpenUserRequest();
            samrOpenUserRequest.DomainHandle = domainHandle;
            samrOpenUserRequest.DesiredAccess = desiredAccess;
            samrOpenUserRequest.UserId = rid;

            samrOpenUserResponse samrOpenUserResponse;

            status = rpc.ExecuteCall((ushort)SamrServiceOpName.samrOpenUser, samrOpenUserRequest, out samrOpenUserResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return samrOpenUserResponse.UserHandle;
        }

        public static NTStatus samrSetInformationUser(RPCCallHelper rpc, SamprHandle userHandle, string password, byte[] sessionKey)
        {
            byte[] lm = new byte[16];
            byte[] pntlm = KrbRelay.Helpers.unhexlify(KrbRelay.Helpers.KerberosPasswordHash(KrbRelay.Interop.KERB_ETYPE.rc4_hmac, password));
            KrbRelay.Natives.RtlEncryptNtOwfPwdWithNtSesKey(pntlm, sessionKey, out byte[] ntlm);

            samrSetInformationUserRequest2 samrSetInformationUserRequest = new samrSetInformationUserRequest2();
            samrSetInformationUserRequest.UserHandle = userHandle;
            samrSetInformationUserRequest.UserInformationClass = 18; // 18 = SAMPR_USER_INTERNAL1_INFORMATION
            samrSetInformationUserRequest.Buffer = new SAMPR_USER_INFO_BUFFER(18);
            samrSetInformationUserRequest.Buffer.Internal1 = new SAMPR_USER_INTERNAL1_INFORMATION();
            samrSetInformationUserRequest.Buffer.Internal1.EncryptedNtOwfPassword = ntlm;
            samrSetInformationUserRequest.Buffer.Internal1.EncryptedLmOwfPassword = lm;
            samrSetInformationUserRequest.Buffer.Internal1.NtPasswordPresent = 1;
            samrSetInformationUserRequest.Buffer.Internal1.LmPasswordPresent = 0;
            samrSetInformationUserRequest.Buffer.Internal1.PasswordExpired = 0;

            samrSetInformationUserResponse2 samrSetInformationUserResponse;

            var status = rpc.ExecuteCall((ushort)SamrServiceOpName.SamrSetInformationUser2, samrSetInformationUserRequest, out samrSetInformationUserResponse);
            return status;
        }

        public static NTStatus samrAddMemberToGroup(RPCCallHelper rpc, SamprHandle groupHandle, uint MemberId, uint Attributes)
        {
            samrAddMemberToGroupRequest samrAddMemberToGroup = new samrAddMemberToGroupRequest();
            samrAddMemberToGroup.GroupHandle = groupHandle;
            samrAddMemberToGroup.MemberId = MemberId;
            samrAddMemberToGroup.Attributes = Attributes;

            samrAddMemberToGroupResponse samrAddMemberToGroupResponse;

            var status = rpc.ExecuteCall((ushort)SamrServiceOpName.samrAddMemberToGroup, samrAddMemberToGroup, out samrAddMemberToGroupResponse);
            return status;
        }

        public static samrCreateUserInDomainResponse samrCreateUserInDomain(RPCCallHelper rpc, SamprHandle domainHandle, string name, uint DesiredAccess, out NTStatus status)
        {
            samrCreateUserInDomainRequest samrCreateUserInDomainRequest = new samrCreateUserInDomainRequest();
            samrCreateUserInDomainRequest.DomainHandle = domainHandle;
            samrCreateUserInDomainRequest.Name = new RPC_UNICODE_STRING(name);
            samrCreateUserInDomainRequest.DesiredAccess = DesiredAccess;

            samrCreateUserInDomainResponse samrCreateUserInDomainResponse;

            status = rpc.ExecuteCall((ushort)SamrServiceOpName.SamrCreateUserInDomain, samrCreateUserInDomainRequest, out samrCreateUserInDomainResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return samrCreateUserInDomainResponse;
        }

        public static NTStatus samrClose(RPCCallHelper rpc, SamprHandle samrHandle)
        {
            samrCloseHandleRequest samrCloseHandleRequest = new samrCloseHandleRequest();
            samrCloseHandleRequest.SamprHandle = samrHandle;

            samrCloseHandleResponse samrCloseHandleResponse;

            var status = rpc.ExecuteCall((ushort)SamrServiceOpName.SamrCloseHandle, samrCloseHandleRequest, out samrCloseHandleResponse);
            return status;
        }
    }
}