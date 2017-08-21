using System;

namespace dk.nita.saml20.Session
{
    internal class UserSession
    {
        private readonly ISessionStoreProvider _sessionStoreProvider;

        internal UserSession(ISessionStoreProvider sessionStoreProvider, Guid sessionId)
        {
            SessionId = sessionId;
            _sessionStoreProvider = sessionStoreProvider ?? throw new ArgumentNullException(nameof(sessionStoreProvider));
        }

        /// <summary>
        /// Session id from cookie
        /// </summary>
        internal Guid SessionId { get; }

        /// <summary>
        /// Inserts og gets a value from the session. Values must be serializable because service provider can choose to implement a distriuted session provider.
        /// </summary>
        /// <param name="key">The key that corresponds to a value.</param>
        /// <returns>A value matching the given key. Null is returned if the key was not found.</returns>
        internal object this[string key]
        {
            get
            {
                if (string.IsNullOrEmpty(key))
                {
                    return null;
                }

                return _sessionStoreProvider.GetSessionProperty(SessionId, key);
            }
            set
            {
                if (!string.IsNullOrEmpty(key))
                {
                    if (value == null)
                    {
                        _sessionStoreProvider.RemoveSessionProperty(SessionId, key);
                    }
                    else
                    {
                        _sessionStoreProvider.SetSessionProperty(SessionId, key, value);
                    }
                }
            }
        }
    }
}