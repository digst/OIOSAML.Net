using System;
using dk.nita.saml20.Session;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class SessionLifetimeTest
    {
        private static readonly DateTime Now = new DateTime(2026, 10, 31, 12, 0, 0, DateTimeKind.Utc);
        private static readonly TimeSpan EightHours = TimeSpan.FromHours(8);

        [Test]
        public void LoginLastsTheMaximumLengthFromTheAuthentication()
        {
            Assert.AreEqual(Now.AddHours(7), Saml20AssertionLite.GetValidUntil(Now.AddHours(-1), null, Now, EightHours));
        }

        [Test]
        public void SessionNotOnOrAfterShortensTheLogin()
        {
            Assert.AreEqual(Now.AddHours(2), Saml20AssertionLite.GetValidUntil(Now, Now.AddHours(2), Now, EightHours));
            Assert.AreEqual(Now.AddHours(8), Saml20AssertionLite.GetValidUntil(Now, Now.AddHours(10), Now, EightHours));
        }

        [Test]
        public void WithoutAnAuthenticationTimeTheLoginStartsNow()
        {
            Assert.AreEqual(Now.AddHours(8), Saml20AssertionLite.GetValidUntil(null, null, Now, EightHours));
        }

        private static ISessionStoreProvider ExpiringStore()
        {
            ISessionStoreProvider store = new InProcSessionStoreProvider();
            store.Initialize(TimeSpan.FromSeconds(-1), new SessionValueFactory());
            return store;
        }

        [Test]
        public void ExpiredSessionIsNotReadOrRevived()
        {
            var store = ExpiringStore();
            var sessionId = Guid.NewGuid();
            store.SetSessionProperty(sessionId, "key", "value");

            Assert.IsNull(store.GetSessionProperty(sessionId, "key"));
            Assert.IsFalse(store.DoesSessionExists(sessionId));

            store.SetSessionProperty(sessionId, "other", "value");
            Assert.IsNull(store.GetSessionProperty(sessionId, "key"));
        }
    }
}
