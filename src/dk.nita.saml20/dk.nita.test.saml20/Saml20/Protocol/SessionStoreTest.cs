using System;
using System.IO;
using System.Web;
using System.Web.Hosting;
using System.Web.Security;
using System.Security.Principal;
using dk.nita.saml20.identity;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.config;
using dk.nita.saml20.Session;
using dk.nita.saml20.session;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class SessionStoreTest
    {
        /// <summary>
        /// An HTTPS request outside IIS, optionally with a session cookie.
        /// </summary>
        private class SecureRequest : SimpleWorkerRequest
        {
            private readonly string _cookie;

            public SecureRequest(string cookie)
                : base("/", Path.GetTempPath(), "login.ashx", "", new StringWriter())
            {
                _cookie = cookie;
            }

            public override bool IsSecure() => true;

            public override string GetKnownRequestHeader(int index)
            {
                if (index == HeaderCookie)
                    return _cookie;
                if (index == HeaderUserAgent)
                    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
                return base.GetKnownRequestHeader(index);
            }
        }

        private static string CookieName => FederationConfig.GetConfig().SessionCookieName;

        private static void StartRequest(string sessionId = null, string cookieValue = null)
        {
            var value = cookieValue ?? sessionId;
            HttpContext.Current = new HttpContext(new SecureRequest(value == null ? null : CookieName + "=" + value));
        }

        [TearDown]
        public void EndRequest()
        {
            HttpContext.Current = null;
        }

        private static Guid StartedSession()
        {
            StartRequest();
            SessionStore.CreateSessionIfNotExists();
            var session = SessionStore.CurrentSession;
            session[SessionConstants.RedirectUrl] = "/protected";
            return session.SessionId;
        }

        [Test]
        public void LoginGivesANewSessionId()
        {
            var before = StartedSession();
            StartRequest(before.ToString());

            SessionStore.RotateSessionId();

            Assert.AreNotEqual(before, SessionStore.CurrentSession.SessionId);
            Assert.AreEqual(SessionStore.CurrentSession.SessionId.ToString(), HttpContext.Current.Response.Cookies[CookieName].Value);
        }

        [Test]
        public void LoginFlowValuesMoveToTheNewSession()
        {
            var before = StartedSession();
            StartRequest(before.ToString());

            SessionStore.RotateSessionId();

            Assert.AreEqual("/protected", SessionStore.CurrentSession[SessionConstants.RedirectUrl]);
        }

        [Test]
        public void OldSessionIsEmptiedAtLogin()
        {
            var before = StartedSession();
            StartRequest(before.ToString());
            SessionStore.CurrentSession[SessionConstants.Saml20AssertionLite] = "earlier login";

            SessionStore.RotateSessionId();
            Assert.IsNull(SessionStore.CurrentSession[SessionConstants.Saml20AssertionLite], "An earlier assertion must not move to the new session.");

            StartRequest(before.ToString());
            Assert.IsFalse(SessionStore.DoesSessionExists());
            Assert.IsNull(SessionStore.CurrentSession[SessionConstants.RedirectUrl]);
        }

        [Test]
        public void SessionIdUnknownToTheStoreIsReplaced()
        {
            var chosenByClient = Guid.NewGuid();
            StartRequest(chosenByClient.ToString());

            SessionStore.CreateSessionIfNotExists();

            Assert.AreNotEqual(chosenByClient, SessionStore.CurrentSession.SessionId);
        }

        [Test]
        public void KnownSessionIsContinued()
        {
            var before = StartedSession();
            StartRequest(before.ToString());

            SessionStore.CreateSessionIfNotExists();

            Assert.AreEqual(before, SessionStore.CurrentSession.SessionId);
        }

        [TestCase("not-a-guid")]
        [TestCase("")]
        public void MalformedSessionCookieMeansNoSession(string cookieValue)
        {
            StartRequest(cookieValue: cookieValue);

            Assert.IsNull(SessionStore.CurrentSession);
            Assert.IsFalse(SessionStore.DoesSessionExists());
        }

        [Test]
        public void LogoutExpiresTheSessionCookie()
        {
            var before = StartedSession();
            StartRequest(before.ToString());

            SessionStore.ExpireSessionCookie();

            var cookie = HttpContext.Current.Response.Cookies[CookieName];
            Assert.AreEqual(string.Empty, cookie.Value);
            Assert.Less(cookie.Expires, DateTime.UtcNow);
            Assert.IsTrue(cookie.Secure);
        }

        private static void LoggedIn(DateTime? validUntil)
        {
            SessionStore.CurrentSession[SessionConstants.Saml20AssertionLite] = new Saml20AssertionLite
            {
                Issuer = "https://idp.example.dk",
                Subject = new NameID { Value = "subject" },
                ValidUntil = validUntil
            };
        }

        private static void WithFormsTicket(string userData)
        {
            var ticket = new FormsAuthenticationTicket(2, "subject", DateTime.Now, DateTime.Now.AddHours(1), false, userData);
            HttpContext.Current.User = new GenericPrincipal(new FormsIdentity(ticket), null);
        }

        [Test]
        public void SessionBeforeLoginCompletesIsNotLoggedIn()
        {
            var before = StartedSession();
            StartRequest(before.ToString());

            Assert.IsTrue(SessionStore.DoesSessionExists());
            Assert.IsFalse(Saml20Identity.IsInitialized());
        }

        [Test]
        public void SessionWithALoginIsLoggedIn()
        {
            StartedSession();
            LoggedIn(DateTime.UtcNow.AddHours(1));

            Assert.IsTrue(Saml20Identity.IsInitialized());
        }

        [Test]
        public void LoginStoredByAnEarlierVersionIsKept()
        {
            StartedSession();
            LoggedIn(null);

            Assert.IsTrue(Saml20Identity.IsInitialized());
        }

        [Test]
        public void LoginEndsAtItsMaximumLength()
        {
            StartedSession();
            LoggedIn(DateTime.UtcNow.AddMinutes(-FederationConfig.GetConfig().AllowedClockSkewMinutes - 1));

            Assert.IsFalse(Saml20Identity.IsInitialized());
            Assert.IsNull(SessionStore.CurrentSession[SessionConstants.Saml20AssertionLite]);
        }

        [Test]
        public void FormsTicketFromThisSessionIsAccepted()
        {
            StartedSession();
            LoggedIn(DateTime.UtcNow.AddHours(1));
            WithFormsTicket(Saml20Identity.FormsTicketBinding());

            Assert.IsTrue(Saml20Identity.IsInitialized());
        }

        [Test]
        public void FormsTicketFromAnotherSessionIsNotAccepted()
        {
            StartedSession();
            var otherSession = Saml20Identity.FormsTicketBinding();
            StartedSession();
            LoggedIn(DateTime.UtcNow.AddHours(1));
            WithFormsTicket(otherSession);

            Assert.IsFalse(Saml20Identity.IsInitialized());
        }

        [Test]
        public void FormsTicketIssuedByTheApplicationIsLeftAlone()
        {
            StartedSession();
            LoggedIn(DateTime.UtcNow.AddHours(1));
            WithFormsTicket("application data");

            Assert.IsTrue(Saml20Identity.IsInitialized());
        }
    }
}
