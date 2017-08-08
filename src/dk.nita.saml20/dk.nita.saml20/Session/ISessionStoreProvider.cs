using System;

namespace dk.nita.saml20.Session
{
    /// <summary>
    /// The interface allows plugging in custom session stores to support distributed setup where in memory sessions are not sufficient. 
    /// Since the provider are used in a shared fashion, all methods must be thread safe, except for <see cref="Initialize"/> which will be invoked ONCE on start up, before any other calls
    /// </summary>
    public interface ISessionStoreProvider
    {
        /// <summary>
        /// Invoked during startup, setting the session timeout after which the session store MUST NOT allow access to session data
        /// </summary>
        void Initialize(TimeSpan sessionTimeout);

        /// <summary>
        /// Add or update the value in the user's session with the given key
        /// </summary>
        /// <param name="sessionId">The id of the user's session</param>
        /// <param name="key">The key of the property to be stored</param>
        /// <param name="value">The value object to be stored</param>
        void SetSessionProperty(Guid sessionId, string key, object value);

        /// <summary>
        /// Removes the value from the user's session with the given key.
        /// </summary>
        /// <param name="sessionId">The id of the user's session</param>
        /// <param name="key">The key of the property to be removed</param>
        void RemoveSessionProperty(Guid sessionId, string key);

        /// <summary>
        /// Returns the property from the user's session with the given key. If value doesn't exist, must return null.
        /// </summary>
        /// <param name="sessionId"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        object GetSessionProperty(Guid sessionId, string key);

        /// <summary>
        /// In order to support back channel logout (SOAP logout) the user id must be associated with the session id.
        /// This method is called by the OIOSAML.net component after the user has been logged in.
        /// </summary>
        /// <param name="userId">The user id. This value is always in lower case because string comparison must be case insensitive (see section 8.1.1 "Requirements for the Subject Element" in the OIOSAML 2.0.9 specification). The user id will be the Distinguished Name (DN) (e.g. "c=DK,o=IT- og Telestyrelsen // CVR:26769388,cn=Brian Nielsen,Serial=CVR:26769388-RID:1203670161406") when using Nemlog-in as IdP.</param>
        /// <param name="sessionId">Id of the user's session</param>
        void AssociateUserIdWithSessionId(string userId, Guid sessionId);
        /// <summary>
        /// Abondon all sessions for the given userId. The same user could be logged into the SP in different browsers or different computers.
        /// If no sessions are found, the method is expected to return successful.
        /// </summary>
        /// <param name="userId">The user id. This value is always in lower case because string comparison must be case insensitive (see section 8.1.1 "Requirements for the Subject Element" in the OIOSAML 2.0.9 specification). The user id will be the Distinguished Name (DN) (e.g. "c=DK,o=IT- og Telestyrelsen // CVR:26769388,cn=Brian Nielsen,Serial=CVR:26769388-RID:1203670161406") when using Nemlog-in as IdP.</param>
        void AbandonSessionsAssociatedWithUserId(string userId);
    }
}