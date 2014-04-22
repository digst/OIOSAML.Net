using System;
using System.Diagnostics;
using dk.nita.saml20.config;
using Trace = dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.session
{
    /// <summary>
    /// This abstract class can be used instead of implementing <see cref="ISessions"/>. This class makes use of cookies to track the session for each user.
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
        public abstract void AbandonCurrentSession();

        /// <summary>
        /// Returns the current session.
        /// </summary>
        /// <returns></returns>
        protected abstract ISession GetSession();

        /// <summary>
        /// Creates a new session.
        /// </summary>
        /// <returns></returns>
        protected abstract ISession CreateSession();

        /// <summary>
        /// The timeout as set in the configuration file.
        /// </summary>
        protected int SessionTimeout
        {
            get { return FederationConfig.GetConfig().SessionTimeout; }
        }

        /// <summary>
        /// <see cref="ISessions.Current"/>
        /// </summary>
        public ISession Current
        {
            get
            {
                return GetSession();
            }
        }

        /// <summary>
        ///   This is the call that actually registers the session - for later logout
        /// </summary>
        /// <returns></returns>
        public ISession RegisterSession()
        {
            ISession session = CreateSession();

            if (session != null && session.New)
            {
                SessionStateUtil.CreateSessionId(session.Id);
                Trace.TraceData(TraceEventType.Information, "New session created with id: " + session.Id);
            }

            return session;
        }

        /// <summary>
        ///  <see cref="ISessions.AbandonAllSessions"/>
        /// </summary>
        /// <param name="userId"></param>
        public abstract void AbandonAllSessions(string userId);

        /// <summary>
        ///  <see cref="ISessions.AssociateUserIdWithCurrentSession"/>
        /// </summary>
        /// <param name="userId"></param>
        public abstract void AssociateUserIdWithCurrentSession(string userId);
    }
}