using System;
using System.Web;

namespace dk.nita.saml20.session
{
    /// <summary>
    /// Session http module for taking care of creating session ids
    /// </summary>
    public class SessionHttpModule : IHttpModule
    {
        /// <summary>
        /// In the Init function, register for HttpApplication events by adding your handlers.
        /// </summary>
        /// <param name="application"></param>
        public void Init(HttpApplication application)
        {
            application.BeginRequest += Application_BeginRequest;
        }

        private void Application_BeginRequest(Object source, EventArgs e)
        {
            // Check if a session exists and create one if it does not.
            if (SessionFactory.Sessions.Current == null)
            {
                SessionStateUtil.CreateSessionId();
                SessionFactory.Sessions.CreateSession();
            }
        }

        /// <summary>
        /// Dispose method
        /// </summary>
        public void Dispose()
        {
        }
    }
}