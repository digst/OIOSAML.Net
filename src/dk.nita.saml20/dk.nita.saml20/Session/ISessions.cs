namespace dk.nita.saml20.session
{
    /// <summary>
    /// This interface is used for working with session state. It makes it possible to access all sessions at any time.
    /// The purpose of this interface is to support SOAP Logout which was not possible with ASP.NET session state.
    /// With this interface it is up to the Service Provider to decide if a simple InProc implementation is enough or OutProc is needed due to a load balancing setup. Also, sticky sessions can be avoided with an OutProc implementation.
    /// Some of the method implementations of this interface must be tread safe. Only those methods that must be thread safe are marked as such. Methods not marked as thread safe are guaranteed only to be called by one thread at a time.
    /// Notice that a user can be logged in in different browsers and hence a user id can be associated with more than one session.
    /// </summary>
    interface ISessions
    {
        /// <summary>
        /// Gets the current session. Accessing the session must result in the session timeout being reset. Thus, it must work according to the sliding expiration principle.
        /// If no session exist a new one must be returned where <see cref="ISession.New"/> must be true.
        /// </summary>
        /// <returns>The current session.</returns>
        ISession Current { get; }

        /// <summary>
        /// Abondon all sessions given a user id. The same user could be logged into the SP in different browsers or different computers.
        /// Returns without error if the user id could not be found.
        /// Must be thread safe.
        /// </summary>
        /// <param name="userId">The user id. Must be lower case because string comparison must be case insensitive (see section 8.1.1 "Requirements for the Subject Element" in the OIOSAML 2.0.9 specification). The user id will be the Distinguished Name (DN) (e.g. "c=DK,o=IT- og Telestyrelsen // CVR:26769388,cn=Brian Nielsen,Serial=CVR:26769388-RID:1203670161406") when using Nemlog-in as IdP.</param>
        void AbandonAllSessions(string userId);

        /// <summary>
        /// Abondon the current session. Returns without error if the current session could not be found.
        /// </summary>
        void AbandonCurrentSession();

        /// <summary>
        /// In order to support back channel logout (SOAP logout) the user id must be associated with the session id.
        /// This method is called by the OIOSAML.net component after the user has been logged in.
        /// The method is strictly not necessary, but the alternative is to read in the complete cache and look for an aseertion with the user id. Instead we create an index with this method so that it is possible to fetch the correct session in one call with the user id as the only knowledge.
        /// </summary>
        /// <param name="userId">The user id. Must be lower case because string comparison must be case insensitive (see section 8.1.1 "Requirements for the Subject Element" in the OIOSAML 2.0.9 specification). The user id will be the Distinguished Name (DN) (e.g. "c=DK,o=IT- og Telestyrelsen // CVR:26769388,cn=Brian Nielsen,Serial=CVR:26769388-RID:1203670161406") when using Nemlog-in as IdP.</param>
        void AssociateUserIdWithCurrentSession(string userId);
    }
}
