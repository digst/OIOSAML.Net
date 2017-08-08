using System;
using System.Web;
using dk.nita.saml20.config;
using dk.nita.saml20.session;
using dk.nita.saml20.Utils;

namespace dk.nita.saml20.Session
{
    internal static class SessionStore
    {
        static SessionStore()
        {
            var type = FederationConfig.GetConfig().SessionType;
            if (!string.IsNullOrEmpty(type))
            {
                try
                {
                    var t = Type.GetType(type);
                    if (t != null)
                    {
                        Sessions = (ISessionStoreProvider)Activator.CreateInstance(t);
                    }
                    else
                    {
                        throw new Exception($"The type {type} is not available as session provider. Please check the type name and assembly");
                    }
                }
                catch (Exception e)
                {
                    Trace.TraceData(System.Diagnostics.TraceEventType.Critical, "Could not instantiate the configured session provider. Message: " + e.Message);
                    throw;
                }
            }
            else
            {
                Sessions = new InProcSessionStoreProvider();
            }

            var sessionTimeoutMinutes = FederationConfig.GetConfig().SessionTimeout;
            Sessions.Initialize(TimeSpan.FromMinutes(sessionTimeoutMinutes));
        }

        private static readonly ISessionStoreProvider Sessions;

        /// <summary>
        /// There current user session. User session is read from cookie. If it doesn't exists, it will be created with the response
        /// </summary>
        /// <returns></returns>
        internal static UserSession CurrentSession
        {
            get
            {
                //If not in context of a web requests, there can't be a current session
                if (HttpContext.Current == null)
                {
                    return null;
                }

                var sessionId = GetSessionIdFromCookie();

                if (!sessionId.HasValue)
                {
                    sessionId = WriteSessionCookie();
                }

                return new UserSession(Sessions, sessionId.Value);
            }
        }

        /// <summary>
        /// Associates the given userId with the current session id
        /// </summary>
        /// <param name="userId"></param>
        internal static void AssociateUserIdWithCurrentSession(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            Sessions.AssociateUserIdWithSessionId(userId.ToLowerInvariant(), CurrentSession.SessionId);
        }

        /// <summary>
        /// Abandons all sessions associated with the given userId
        /// </summary>
        /// <param name="userId"></param>
        public static void AbandonAllSessions(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            Sessions.AbandonSessionsAssociatedWithUserId(userId.ToLowerInvariant());
        }

        private static Guid? GetSessionIdFromCookie()
        {
            HttpCookie httpCookie = HttpContext.Current.Request.Cookies[SessionConstants.SessionCookieName];
            if (httpCookie != null)
                return new Guid(httpCookie.Value);

            return null;
        }

        private static Guid WriteSessionCookie()
        {
            var sessionId = Guid.NewGuid();

            HttpContext.Current.Request.Cookies.Remove(SessionConstants.SessionCookieName); // Remove cookie from request when creating a new session id. This is necessary because adding a cookie with the same name does not override cookies in the request.
            var httpCookie = new HttpCookie(SessionConstants.SessionCookieName, sessionId.ToString())
            {
                Secure = true,
                HttpOnly = true
            };
            HttpContext.Current.Response.Cookies.Add(httpCookie); // When a cookie is added to the response it is automatically added to the request. Thus, SessionId is available immeditly when reading cookies from the request.

            return sessionId;
        }
    }
}