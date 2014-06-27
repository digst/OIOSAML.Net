namespace dk.nita.saml20.session
{
    /// <summary>
    /// Class for storing constants regarding session handleing
    /// </summary>
    public class SessionConstants
    {
        /// <summary>
        /// Name of cookie that stores the session id
        /// </summary>
        public const string SessionCookieName = "oiosamlSession";

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
    }
}
