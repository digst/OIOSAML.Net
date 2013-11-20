using System;

namespace dk.nita.saml20.session
{
    /// <summary>
    /// Represents a session. The session is not thread safe as we only expect one user at a time 
    /// </summary>
    public interface ISession
    {
        /// <summary>
        /// Inserts og gets a value from the session. Values must be serializable because service provider can choose to implement a distriuted session provider.
        /// </summary>
        /// <param name="key">The key that corresponds to a value.</param>
        /// <returns>A value matching the given key. Null is returned if the key was not found.</returns>
        object this[string key] { get; set; }

        /// <summary>
        /// Removes the key and its associted value from the session.
        /// Succeeds even if the key was not found.
        /// </summary>
        /// <param name="key">The key that will be removed from the session.</param>
        void Remove(string key);

        /// <summary>
        /// Indicates if a new session has been created because no session existed. In subsequent calls to <see cref="ISessions.Current"/> the value will be false.
        /// </summary>
        bool New { get; set;  }

        /// <summary>
        /// The session id of the session
        /// </summary>
        Guid Id { get; }
    }
}
