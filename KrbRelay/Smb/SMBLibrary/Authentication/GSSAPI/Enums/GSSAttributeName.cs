namespace SMBLibrary.Authentication.GSSAPI
{
    public enum GSSAttributeName
    {
        AccessToken,
        DomainName,
        IsAnonymous,

        /// <summary>
        /// Permit access to this user via the guest user account if the normal authentication process fails.
        /// </summary>
        IsGuest,

        MachineName,
        OSVersion,
        SessionKey,
        UserName,
    }
}