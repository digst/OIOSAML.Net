using System;
using System.Linq;
using System.Security.Cryptography;
using System.Reflection;
using System.Web;
using dk.nita.saml20.session;
using dk.nita.saml20.config;
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

        internal static void CreateSessionIfNotExists()
        {
            if (HttpContext.Current == null)
            {
                throw new InvalidOperationException("A session cannot be created when running outside the context of a asp.net request");
            }

            var sessionId = GetSessionIdFromCookie();

            // Only continue a session the store knows; never create one for an id chosen by the client.
            if (!sessionId.HasValue || !SessionStoreProvider.DoesSessionExists(sessionId.Value))
            {
                WriteSessionCookie();
            }
        }

        /// <summary>
        /// Gives the user a new session id at login, so that a session id known before the login is of no use after it (session fixation).
        /// The values of the login flow move to the new session, and the old session is emptied. An assertion from an earlier login is not moved.
        /// </summary>
        internal static void RotateSessionId()
        {
            var previous = CurrentSession;
            WriteSessionCookie();
            if (previous == null)
                return;

            var current = CurrentSession;
            foreach (var key in SessionKeys)
            {
                var value = previous[key];
                if (value == null)
                    continue;

                if (key != SessionConstants.Saml20AssertionLite)
                    current[key] = value;
                previous[key] = null;
            }
        }

        /// <summary>
        /// Tells the browser to delete the session cookie, at logout.
        /// </summary>
        internal static void ExpireSessionCookie()
        {
            if (HttpContext.Current == null)
                return;

            HttpContext.Current.Response.Cookies.Set(new HttpCookie(GetSessionCookieName(), string.Empty)
            {
                Expires = DateTime.UtcNow.AddYears(-1),
                Secure = true,
                HttpOnly = true,
            });
        }

        /// <summary>
        /// The keys the library stores in a session.
        /// </summary>
        private static readonly string[] SessionKeys = typeof(SessionConstants)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue())
            .ToArray();

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
        internal static void AbandonAllSessions(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            SessionStoreProvider.AbandonSessionsAssociatedWithUserId(userId.ToLowerInvariant());
        }

        private static Guid? GetSessionIdFromCookie()
        {
            HttpCookie httpCookie = HttpContext.Current.Request.Cookies[GetSessionCookieName()];
            if (httpCookie != null && Guid.TryParse(httpCookie.Value, out var sessionId))
                return sessionId;

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
                HttpOnly = true,
            };

            var shouldSendSameSiteNoneCookie = BrowserSupportUtil.ShouldSendSameSiteNone(HttpContext.Current.Request.UserAgent);
            if (shouldSendSameSiteNoneCookie)
            {
                httpCookie.SameSite = SameSiteMode.None;
            }

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
        /// Asserts that the user has a session.
        /// </summary>
        /// <exception cref="Saml20Exception">Is thrown if no session exists.</exception>
        internal static void AssertSessionExists()
        {
            if (!DoesSessionExists())
            {
                if (CurrentSession == null)
                {
                    throw new Saml20Exception(
                        "The user doesn't have a session in context of a cookie ... which is required at this point in the pipeline. Plausible reason is that OIOSAML.Net is not running under https. The session cookie is marked with 'secure only'.");
                }
                else if (!SessionStoreProvider.DoesSessionExists(CurrentSession.SessionId))
                {
                    throw new Saml20Exception(
                        "The user doesn't have a session in session store which is required at this point in the pipeline. Plausible reason is that the user's session has expired. \nIf the application is running in a web farm ensure distributed sessions is supported by the session store provider.");
                }
                else
                {
                    throw new Saml20Exception("The user doesn't have a session for unknown reasons.");
                }
            }
        }

        /// <summary>
        /// A value that identifies the current session without revealing its id, or an empty string without a session.
        /// </summary>
        internal static string SessionBinding()
        {
            if (CurrentSession == null)
                return string.Empty;

            using (var sha256 = SHA256.Create())
                return Convert.ToBase64String(sha256.ComputeHash(CurrentSession.SessionId.ToByteArray()));
        }

        /// <summary>
        /// Checks whether or not the user has a session
        /// SamlAssertionLite is the only item in the session store after a succesful login flow. This is what implicit makes the session exist.
        /// </summary>
        internal static bool DoesSessionExists()
        {
            return CurrentSession != null && SessionStoreProvider.DoesSessionExists(CurrentSession.SessionId);
        }
    }
}