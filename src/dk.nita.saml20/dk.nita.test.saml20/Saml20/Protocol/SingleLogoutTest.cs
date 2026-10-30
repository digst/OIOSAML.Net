using System;
using System.Security.Cryptography;
using dk.nita.saml20;
using dk.nita.saml20.Bindings;
using dk.nita.saml20.protocol;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Session;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class SingleLogoutTest
    {
        private const string Idp = "https://idp.example.dk";
        private const string Persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
        private static readonly Uri SloUrl = new Uri("https://sp.example.dk/logout.ashx");
        private static readonly Uri[] SloUrls = { SloUrl };
        private static readonly TimeSpan Skew = TimeSpan.FromMinutes(1);
        private static readonly DateTime Now = new DateTime(2026, 10, 31, 12, 0, 0, DateTimeKind.Utc);

        private static LogoutRequest Request()
        {
            return new LogoutRequest
            {
                ID = "_request",
                Destination = SloUrl.ToString(),
                IssueInstant = Now.AddSeconds(-10),
                Issuer = new NameID { Value = Idp },
                Item = new NameID { Value = "subject", Format = Persistent },
                SessionIndex = new[] { "session-1" }
            };
        }

        private static Saml20AssertionLite Session()
        {
            return new Saml20AssertionLite { Issuer = Idp, Subject = new NameID { Value = "subject", Format = Persistent }, SessionIndex = "session-1" };
        }

        private static string Check(LogoutRequest request, bool destinationRequired = true)
        {
            return Saml20LogoutHandler.CheckLogoutRequest(request, SloUrls, destinationRequired, Now, Skew);
        }

        [Test]
        public void ValidLogoutRequestIsAccepted()
        {
            Assert.IsNull(Check(Request()));
        }

        [Test]
        public void LogoutRequestWithoutIdIsRefused()
        {
            var request = Request();
            request.ID = null;
            Assert.IsNotNull(Check(request));
        }

        [Test]
        public void LogoutRequestForAnotherDestinationIsRefused()
        {
            var request = Request();
            request.Destination = "https://other.example.dk/logout.ashx";
            Assert.IsNotNull(Check(request));
            Assert.IsNotNull(Check(request, destinationRequired: false));
        }

        [Test]
        public void DestinationIsRequiredOnlyWhereTheBindingRequiresIt()
        {
            var request = Request();
            request.Destination = null;
            Assert.IsNotNull(Check(request));
            Assert.IsNull(Check(request, destinationRequired: false));
        }

        [Test]
        public void LogoutRequestIssuedTooLongAgoOrInTheFutureIsRefused()
        {
            var request = Request();
            request.IssueInstant = Now - Saml20LogoutHandler.LogoutRequestMaximumAge - Skew;
            Assert.IsNotNull(Check(request));

            request.IssueInstant = Now + Skew + TimeSpan.FromSeconds(1);
            Assert.IsNotNull(Check(request));

            request.IssueInstant = null;
            Assert.IsNotNull(Check(request));
        }

        [Test]
        public void ExpiredLogoutRequestIsRefused()
        {
            var request = Request();
            request.NotOnOrAfter = Now - Skew;
            Assert.IsNotNull(Check(request));

            request.NotOnOrAfter = Now.AddMinutes(1);
            Assert.IsNull(Check(request));
        }

        [Test]
        public void LogoutRequestMustNameTheSubjectOfTheSession()
        {
            Assert.IsTrue(Saml20LogoutHandler.NamesSubject(Request(), Session()));

            var otherValue = Request();
            otherValue.Item = new NameID { Value = "someone else", Format = Persistent };
            Assert.IsFalse(Saml20LogoutHandler.NamesSubject(otherValue, Session()));

            var otherFormat = Request();
            otherFormat.Item = new NameID { Value = "subject", Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" };
            Assert.IsFalse(Saml20LogoutHandler.NamesSubject(otherFormat, Session()));

            var otherSession = Request();
            otherSession.SessionIndex = new[] { "session-2" };
            Assert.IsFalse(Saml20LogoutHandler.NamesSubject(otherSession, Session()));

            var noSessionIndex = Request();
            noSessionIndex.SessionIndex = null;
            Assert.IsTrue(Saml20LogoutHandler.NamesSubject(noSessionIndex, Session()));

            var noNameId = Request();
            noNameId.Item = null;
            Assert.IsFalse(Saml20LogoutHandler.NamesSubject(noNameId, Session()));
        }

        private static LogoutResponse Response()
        {
            return new LogoutResponse { InResponseTo = "_sent", Issuer = new NameID { Value = Idp }, Destination = SloUrl.ToString() };
        }

        [Test]
        public void LogoutResponseMustAnswerTheSentRequest()
        {
            Assert.IsNull(Saml20LogoutHandler.CheckLogoutResponse(Response(), "_sent", Idp, SloUrls, true));
            Assert.IsNotNull(Saml20LogoutHandler.CheckLogoutResponse(Response(), null, null, SloUrls, true));
            Assert.IsNotNull(Saml20LogoutHandler.CheckLogoutResponse(Response(), "_other", Idp, SloUrls, true));
            Assert.IsNotNull(Saml20LogoutHandler.CheckLogoutResponse(Response(), "_sent", "https://other-idp.example.dk", SloUrls, true));

            var otherDestination = Response();
            otherDestination.Destination = "https://other.example.dk/logout.ashx";
            Assert.IsNotNull(Saml20LogoutHandler.CheckLogoutResponse(otherDestination, "_sent", Idp, SloUrls, true));
        }

        private static string SignedQuery(RSA key)
        {
            var builder = new HttpRedirectBindingBuilder { signingKey = key, Request = "<LogoutRequest/>" };
            return builder.ToQuery();
        }

        [Test]
        public void SignedRedirectMessageIsVerified()
        {
            using (var key = RSA.Create(2048))
            {
                var parser = new HttpRedirectBindingParser(new Uri("https://sp.example.dk/logout.ashx?other=1&" + SignedQuery(key)));
                Assert.IsTrue(parser.CheckSignature(key));
                Assert.AreEqual("<LogoutRequest/>", parser.Message);
            }
        }

        [TestCase("SAMLRequest")]
        [TestCase("samlrequest")]
        [TestCase("SAMLREQUEST")]
        [TestCase("SAMLResponse")]
        [TestCase("relaystate")]
        [TestCase("sigalg")]
        [TestCase("Signature")]
        public void RedirectParameterThatAppearsTwiceInAnyCaseIsRefused(string name)
        {
            using (var key = RSA.Create(2048))
            {
                var query = SignedQuery(key) + "&" + name + "=x";
                Assert.Throws<Saml20FormatException>(() => new HttpRedirectBindingParser(new Uri("https://sp.example.dk/logout.ashx?" + query)));
            }
        }

        [Test]
        public void RedirectSignatureWithoutSigAlgIsRefused()
        {
            Assert.Throws<Saml20FormatException>(() => new HttpRedirectBindingParser(new Uri("https://sp.example.dk/logout.ashx?SAMLRequest=x&Signature=y")));
        }

        [Test]
        public void RedirectQueryWithoutMessageIsRefused()
        {
            Assert.Throws<Saml20FormatException>(() => new HttpRedirectBindingParser(new Uri("https://sp.example.dk/logout.ashx")));
        }
    }
}
