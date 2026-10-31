namespace dk.nita.saml20.session
{
    /// <summary>
    /// Class for storing constants regarding session handleing
    /// </summary>
    public class SessionConstants
    {
        /// <summary>
        /// 
        /// </summary>
        public const string Saml20AssertionLite = "SamlAssertionLite";

        /// <summary>
        /// ???
        /// </summary>
        public const string RedirectUrl = "RedirectUrl";

        /// <summary>
        /// Session key used to save the current message id with the purpose of preventing replay attacks
        /// </summary>
        public const string ExpectedInResponseTo = "ExpectedInResponseTo";

        /// <summary>
        /// Session key used to save the demanded level of assurance
        /// </summary>
        public const string ExpectedNsisLoa = "ExpectedLevelOfAssurance";

        /// <summary>
        /// Session key used to save the id of the IdP the AuthnRequest was sent to
        /// </summary>
        public const string ExpectedIdpId = "ExpectedIdpId";

        /// <summary>
        /// Session key used to save the id of the LogoutRequest sent at a logout this service provider initiates
        /// </summary>
        public const string PendingLogoutRequestId = "PendingLogoutRequestId";

        /// <summary>
        /// Session key used to save the id of the IdP that LogoutRequest was sent to
        /// </summary>
        public const string PendingLogoutIdpId = "PendingLogoutIdpId";
    }
}
