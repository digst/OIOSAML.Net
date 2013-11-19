namespace dk.nita.saml20.session
{
    /// <summary>
    /// Represents a session. The session is not thread safe as we only expect one user at a time 
    /// </summary>
    public interface ISession
    {
        /// <summary>
        /// Inserts og gets a value from the session.
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
    }
}
