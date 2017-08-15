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
                        SessionStoreProvider = (ISessionStoreProvider)Activator.CreateInstance(t);
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
                SessionStoreProvider = new InProcSessionStoreProvider();
            }

            var sessionTimeoutMinutes = FederationConfig.GetConfig().SessionTimeout;
            SessionStoreProvider.Initialize(TimeSpan.FromMinutes(sessionTimeoutMinutes), new SessionValueFactory());
        }

        private static readonly ISessionStoreProvider SessionStoreProvider;

        /// <summary>
        /// There current user session. User session is read from cookie. If it doesn't exists, null is returned
        /// </summary>
        /// <returns></returns>
        internal static UserSession CurrentSession
        {
            get
            {
                //If not in context of a web requests, there can't be a current session
                if (HttpContext.Current != null)
                {
                    var sessionId = GetSessionIdFromCookie();

                    if (sessionId.HasValue)
                    {
                        return new UserSession(SessionStoreProvider, sessionId.Value);
                    }
                }

                return null;
            }
        }

        public static void CreateSessionIfNotExists()
        {
            if (HttpContext.Current == null)
            {
                throw new InvalidOperationException("A session cannot be created when running outside the context of a asp.net request");
            }

            var sessionId = GetSessionIdFromCookie();

            if (!sessionId.HasValue)
            {
                WriteSessionCookie();
            }
        }

        /// <summary>
        /// Associates the given userId with the current session id
        /// </summary>
        /// <param name="userId"></param>
        internal static void AssociateUserIdWithCurrentSession(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            SessionStoreProvider.AssociateUserIdWithSessionId(userId.ToLowerInvariant(), CurrentSession.SessionId);
        }

        /// <summary>
        /// Abandons all sessions associated with the given userId
        /// </summary>
        /// <param name="userId"></param>
        public static void AbandonAllSessions(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            SessionStoreProvider.AbandonSessionsAssociatedWithUserId(userId.ToLowerInvariant());
        }

        private static Guid? GetSessionIdFromCookie()
        {
            HttpCookie httpCookie = HttpContext.Current.Request.Cookies[GetSessionCookieName()];
            if (httpCookie != null)
                return new Guid(httpCookie.Value);

            return null;
        }

        private static void WriteSessionCookie()
        {
            if (!HttpContext.Current.Request.IsSecureConnection)
            {
                throw new Saml20Exception("The service provider must use https since session cookie is not allowed on a unsecure transport");
            }

            var sessionId = Guid.NewGuid();

            HttpContext.Current.Request.Cookies.Remove(GetSessionCookieName()); // Remove cookie from request when creating a new session id. This is necessary because adding a cookie with the same name does not override cookies in the request.
            var httpCookie = new HttpCookie(GetSessionCookieName(), sessionId.ToString())
            {
                Secure = true,
                HttpOnly = true
            };
            HttpContext.Current.Response.Cookies.Add(httpCookie); // When a cookie is added to the response it is automatically added to the request. Thus, SessionId is available immeditly when reading cookies from the request.
        }

        private static string GetSessionCookieName()
        {
            var name = FederationConfig.GetConfig().SessionCookieName;

            if (string.IsNullOrWhiteSpace(name))
            {
                throw new Saml20Exception($"The session cookie name '{name}' is not valid. Ensure a valid cookie name is set in the configuration element 'SessionCookieName'");
            }

            return name;
        }

        /// <summary>
        /// Validates the user has an active session, else throws an exception
        /// </summary>
        public static void ValidateSessionExists()
        {
            if (CurrentSession == null)
            {
                throw new Saml20Exception("The user doesn't have a session which is required at this point in the pipeline. Plausible reason is that the user's session has expired. \nIf the application is running in a web farm ensure distributed sessions is supported by the session store provider.");
            }
        }
    }
}