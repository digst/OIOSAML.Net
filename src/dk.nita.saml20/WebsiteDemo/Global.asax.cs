using System;
using System.Collections.Generic;
using System.Web;
using System.Web.Security;
using System.Web.SessionState;
using dk.nita.saml20.Utils;

namespace WebsiteDemo
{
    public class Global : System.Web.HttpApplication
    {
        /// <summary>
        /// Example of a simple IDP selection eventhandler, that just selects the first of the possible IDP Endpoints
        /// </summary>
        private readonly IDPSelectionEventHandler _idpSelectionEventHandler = (idpEndpoints => idpEndpoints.IDPEndPoints[0]);

        protected void Application_Start(object sender, EventArgs e)
        {
            
        }

        protected void Session_Start(object sender, EventArgs e)
        {

        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {

        }

        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {

        }

        protected void Application_Error(object sender, EventArgs e)
        {

        }

        protected void Session_End(object sender, EventArgs e)
        {

        }

        protected void Application_End(object sender, EventArgs e)
        {
            
        }
    }
}