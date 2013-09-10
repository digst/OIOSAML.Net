using System;
using System.Collections.Generic;
using System.Web;
using dk.nita.saml20.Actions;
using dk.nita.saml20.identity;
using dk.nita.saml20.Logging;

namespace WebsiteDemo
{
    public class LogAction: IAction
    {
        #region IAction Members

        public void LoginAction(dk.nita.saml20.protocol.AbstractEndpointHandler handler, HttpContext context, dk.nita.saml20.Saml20Assertion assertion)
        {
            // Since FormsAuthentication is used in this sample, the user name to log can be found in context.User.Identity.Name.
            // This user will not be set until after a new redirect, so unfortunately we cannot just log it here,
            // but will have to do in MyPage.Load in order to log the local user id
        }

        public void LogoutAction(dk.nita.saml20.protocol.AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated)
        {
            // Example of logging required by the requirements SLO1 ("Id of internal user account")
            // Since FormsAuthentication is used in this sample, the user name to log can be found in context.User.Identity.Name
            // The login will be not be cleared until next redirect due to the way FormsAuthentication works, so we will have to check Saml20Identity.IsInitialized() too
            AuditLogging.logEntry(Direction.IN, Operation.LOGOUT, "ServiceProvider logout",
                "SP local user id: " + (context.User.Identity.IsAuthenticated ? context.User.Identity.Name : "none") + " login status: " + Saml20Identity.IsInitialized());
        }

        public string Name
        {
            get { return "LogAction"; }
            set
            {
                
            }
        }

        #endregion
    }
}
