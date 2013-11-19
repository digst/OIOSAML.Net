using System;
using dk.nita.saml20.config;

namespace dk.nita.saml20.session
{
    /// <summary>
    /// This abstract class must be used by all session implementations. It encapsulates the logic of how session id and session timeout is retrieved.
    /// </summary>
    public abstract class AbstractSessions : ISessions
    {
        /// <summary>
        /// Session id that session providers must use for identifying the session.
        /// </summary>
        protected Guid? SessionId
        {
            get { return SessionStateUtil.SessionId; }
        }

        /// <summary>
        /// <see cref="ISessions.AbandonCurrentSession"/>
        /// </summary>
        public void AbandonCurrentSession()
        {
            AbandonSession(SessionId.GetValueOrDefault());
        }

        /// <summary>
        /// Checks whether a current session exists.
        /// </summary>
        /// <returns>True if a session exists.</returns>
        protected bool SessionExists()
        {
            return Current != null;
        }

        /// <summary>
        /// The timeout as set in the configuration file.
        /// </summary>
        protected int SessionTimeout
        {
            get { return SAML20FederationConfig.GetConfig().SessionTimeout; }
        }

        /// <summary>
        /// <see cref="ISessions.Current"/>
        /// </summary>
        public abstract ISession Current { get; }
        
        /// <summary>
        ///  <see cref="ISessions.AbandonSession"/>
        /// </summary>
        /// <param name="sessionId"></param>
        public abstract void AbandonSession(Guid sessionId);

        /// <summary>
        /// <see cref="ISessions.CreateSession"/>
        /// </summary>
        public abstract void CreateSession();
    }
}