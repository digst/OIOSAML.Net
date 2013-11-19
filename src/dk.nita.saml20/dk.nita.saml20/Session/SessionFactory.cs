using System;

namespace dk.nita.saml20.session
{
    /// <summary>
    /// Factory for getting the concrete session implementation.
    /// </summary>
    class SessionFactory
    {
        private static readonly ISessions _sessions = (ISessions)Activator.CreateInstance("dk.nita.saml20.ext.appfabricsessioncache", "dk.nita.saml20.ext.appfabricsessioncache.AppFabricSessions").Unwrap();
        //private static readonly ISessions _sessions = (ISessions) Activator.CreateInstance("dk.nita.saml20", "dk.nita.saml20.session.inproc.InProcSessions").Unwrap();

        /// <summary>
        /// Returns the only instance of the session.
        /// </summary>
        internal static ISessions Sessions
        {
            get { return _sessions; }
        }
    }
}
