using System.Collections.Generic;
using System.Web;
using IdentityProviderDemo.Logic;

namespace IdentityProviderDemo.config
{
    /// <summary>
    /// Handles the list of federation partners where the user is logged in.
    /// </summary>
    public class UserSessionsHandler
    {
        private const string LOGGEDINSESSIONSKEY = "dk.nita.saml20.loggedinsessions";

        private const string AUTHENTICATEDKEY = "dk.nita.saml20.authenticatedsession";

        public static User CurrentUser
        {
            get { return HttpContext.Current.Session[AUTHENTICATEDKEY] as User; }
            set { HttpContext.Current.Session[AUTHENTICATEDKEY] = value; }
        }

        /// <summary>
        /// Removes the session variables associated with the current user.
        /// </summary>
        public static void DestroySession()
        {
            HttpContext.Current.Session.Remove(AUTHENTICATEDKEY);
            HttpContext.Current.Session.Remove(LOGGEDINSESSIONSKEY);
        }

        /// <summary>
        /// Adds the SP with the given entity ID to the list of the user's logged in sessions.
        /// </summary>
        public static void AddLoggedInSession(string id)
        {
            List<string> serviceproviders = HttpContext.Current.Session[LOGGEDINSESSIONSKEY] as List<string>;
            if (serviceproviders == null)
            {
                serviceproviders = new List<string>(1);
                HttpContext.Current.Session[LOGGEDINSESSIONSKEY] = serviceproviders;
            }

            serviceproviders.Add(id);
        }

        /// <summary>
        /// Removes the SP with the given entity ID from the list of the user's logged in sessions.
        /// </summary>
        public static void RemoveLoggedInSession(string id)
        {
            List<string> serviceproviders = GetLoggedInSessions();
            serviceproviders.Remove(id);
        }

        public static List<string> GetLoggedInSessions()
        {
            List<string> serviceproviders = HttpContext.Current.Session[LOGGEDINSESSIONSKEY] as List<string>;
            if (serviceproviders == null)
            {
                serviceproviders = new List<string>(1);
                HttpContext.Current.Session[LOGGEDINSESSIONSKEY] = serviceproviders;
            }
            return serviceproviders;
        }
    }
}
