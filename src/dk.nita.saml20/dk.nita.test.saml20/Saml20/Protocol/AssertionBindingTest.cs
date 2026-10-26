using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;
using dk.nita.saml20.Schema.Core;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class AssertionBindingTest
    {
        private const string RequestId = "id0123456789abcdef";
        private const string AcsUrl = "https://sp.example.dk:20002/login.ashx";
        private static readonly ICollection<Uri> Acs = new List<Uri> { new Uri(AcsUrl) };
        private static readonly DateTime NotOnOrAfter = DateTime.UtcNow.AddMinutes(5);

        private static Assertion AssertionWith(params SubjectConfirmation[] confirmations)
        {
            var items = new List<object> { new NameID { Value = "user" } };
            items.AddRange(confirmations);
            return new Assertion { Subject = new Subject { Items = items.ToArray() } };
        }

        private static SubjectConfirmation Bearer(string inResponseTo, string recipient, string method = SubjectConfirmation.BEARER_METHOD, DateTime? notOnOrAfter = null, bool withNotOnOrAfter = true)
        {
            return new SubjectConfirmation
            {
                Method = method,
                SubjectConfirmationData = new SubjectConfirmationData
                {
                    InResponseTo = inResponseTo,
                    Recipient = recipient,
                    NotOnOrAfter = withNotOnOrAfter ? notOnOrAfter ?? NotOnOrAfter : (DateTime?)null,
                }
            };
        }

        private static string Check(Assertion assertion, string expectedRequestId = RequestId)
        {
            return Saml20SignonHandler.CheckBearerConfirmation(assertion, expectedRequestId, Acs, out _);
        }

        [Test]
        public void BearerConfirmationAnsweringTheRequestIsAccepted()
        {
            var failure = Saml20SignonHandler.CheckBearerConfirmation(AssertionWith(Bearer(RequestId, AcsUrl)), RequestId, Acs, out var confirmation);

            Assert.IsNull(failure);
            Assert.AreEqual(RequestId, confirmation.InResponseTo);
        }

        [Test]
        public void RecipientIsComparedAsAUrl()
        {
            Assert.IsNull(Check(AssertionWith(Bearer(RequestId, "https://SP.example.dk:20002/login.ashx"))));
        }

        [TestCase("idOtherRequest")]
        [TestCase(null)]
        public void BearerConfirmationForAnotherRequestIsRejected(string inResponseTo)
        {
            StringAssert.Contains("[OIO-IDP-17]", Check(AssertionWith(Bearer(inResponseTo, AcsUrl))));
        }

        [TestCase(null)]
        [TestCase("")]
        public void MissingExpectedRequestIsRejected(string expectedRequestId)
        {
            Assert.IsNotNull(Check(AssertionWith(Bearer(expectedRequestId, AcsUrl)), expectedRequestId));
        }

        [TestCase("https://other.example.dk/login.ashx")]
        [TestCase("https://sp.example.dk:20002/logout.ashx")]
        [TestCase("https://sp.example.dk:20002/Login.ashx")]
        [TestCase("https://sp.example.dk")]
        [TestCase("not a url")]
        [TestCase(null)]
        public void RecipientOtherThanTheAcsIsRejected(string recipient)
        {
            Assert.IsNotNull(Check(AssertionWith(Bearer(RequestId, recipient))));
        }

        [Test]
        public void RecipientMismatchNamesTheReceivedAndExpectedUrls()
        {
            var failure = Check(AssertionWith(Bearer(RequestId, "https://other.example.dk/login.ashx")));

            StringAssert.Contains("https://other.example.dk/login.ashx", failure);
            StringAssert.Contains(AcsUrl, failure);
        }

        [Test]
        public void BearerConfirmationWithoutNotOnOrAfterIsRejected()
        {
            var failure = Saml20SignonHandler.CheckBearerConfirmation(AssertionWith(Bearer(RequestId, AcsUrl, withNotOnOrAfter: false)), RequestId, Acs, out var confirmation);

            StringAssert.Contains("NotOnOrAfter", failure);
            Assert.IsNull(confirmation);
        }

        [Test]
        public void NonBearerConfirmationIsIgnored()
        {
            var holderOfKey = Bearer(RequestId, AcsUrl, "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
            Assert.IsNotNull(Check(AssertionWith(holderOfKey)));
        }

        [Test]
        public void InResponseToAndRecipientMustBeInTheSameConfirmation()
        {
            var assertion = AssertionWith(Bearer(RequestId, "https://other.example.dk/login.ashx"), Bearer("idOtherRequest", AcsUrl));
            Assert.IsNotNull(Check(assertion));
        }

        [Test]
        public void TheMatchingConfirmationGivesTheValidity()
        {
            var later = NotOnOrAfter.AddMinutes(10);
            var assertion = AssertionWith(Bearer("idOtherRequest", "https://other.example.dk/login.ashx"), Bearer(RequestId, AcsUrl, notOnOrAfter: later));

            Assert.IsNull(Saml20SignonHandler.CheckBearerConfirmation(assertion, RequestId, Acs, out var confirmation));
            Assert.AreEqual(later, confirmation.NotOnOrAfter);
        }

        [Test]
        public void AssertionWithoutSubjectIsRejected()
        {
            Assert.IsNotNull(Check(new Assertion()));
        }

        private static ServiceProviderElement ServiceProvider(string server, params string[] signOnPaths)
        {
            var endpoints = new List<Saml20ServiceEndpoint> { new Saml20ServiceEndpoint { endpointType = EndpointType.LOGOUT, localPath = "/logout.ashx" } };
            foreach (var path in signOnPaths)
                endpoints.Add(new Saml20ServiceEndpoint { endpointType = EndpointType.SIGNON, localPath = path });
            return new ServiceProviderElement { Server = server, serviceEndpoints = endpoints };
        }

        [Test]
        public void AssertionConsumerServiceUrlsAreTheSignOnEndpoints()
        {
            CollectionAssert.AreEqual(new[] { new Uri(AcsUrl) }, Saml20SignonHandler.AssertionConsumerServiceUrls(ServiceProvider("https://sp.example.dk:20002", "/login.ashx")));
        }

        [TestCase("https://sp.example.dk/app/", "login.ashx", "https://sp.example.dk/app/login.ashx")]
        [TestCase("https://sp.example.dk/app/", "/login.ashx", "https://sp.example.dk/login.ashx")]
        [TestCase("https://sp.example.dk:443", "/login.ashx", "https://sp.example.dk/login.ashx")]
        public void EndpointUrlIsTheServerCombinedWithTheLocalPathAsInTheMetadata(string server, string localPath, string expected)
        {
            var serviceProvider = ServiceProvider(server, localPath);

            Assert.AreEqual(new Uri(expected), Saml20SignonHandler.AssertionConsumerServiceUrls(serviceProvider).Single());
        }

        [Test]
        public void EverySignOnEndpointIsAnAssertionConsumerService()
        {
            Assert.AreEqual(2, Saml20SignonHandler.AssertionConsumerServiceUrls(ServiceProvider("https://sp.example.dk", "/login.ashx", "/login2.ashx")).Count);
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("sp.example.dk")]
        public void MissingOrRelativeServerIsAConfigurationError(string server)
        {
            Assert.Throws<ConfigurationErrorsException>(() => Saml20SignonHandler.AssertionConsumerServiceUrls(ServiceProvider(server, "/login.ashx")));
        }

        [Test]
        public void AnAssertionIsAcceptedOnlyOnce()
        {
            var id = "id" + Guid.NewGuid().ToString("N");

            Assert.IsTrue(Saml20SignonHandler.TryRegisterAssertion(id, DateTime.UtcNow.AddMinutes(5)));
            Assert.IsFalse(Saml20SignonHandler.TryRegisterAssertion(id, DateTime.UtcNow.AddMinutes(5)));
            Assert.IsTrue(Saml20SignonHandler.TryRegisterAssertion("id" + Guid.NewGuid().ToString("N"), DateTime.UtcNow.AddMinutes(5)));
        }

        [TestCase("idResolve", "idResolve", true)]
        [TestCase("idResolve", "idOther", false)]
        [TestCase("idResolve", null, false)]
        [TestCase(null, null, false)]
        [TestCase(null, "idResolve", false)]
        public void ArtifactResponseMustAnswerTheArtifactResolveSent(string artifactResolveId, string inResponseTo, bool expected)
        {
            Assert.AreEqual(expected, Saml20SignonHandler.AnswersArtifactResolve(artifactResolveId, inResponseTo));
        }

        private static XmlElement Response(string content)
        {
            var doc = new XmlDocument();
            doc.LoadXml("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + content + "</samlp:Response>");
            return doc.DocumentElement;
        }

        [Test]
        public void EncryptedAssertionIsReturned()
        {
            Assert.AreEqual("EncryptedAssertion", Saml20SignonHandler.GetEncryptedAssertion(Response("<saml:EncryptedAssertion/>")).LocalName);
        }

        [TestCase("<saml:Assertion/>")]
        [TestCase("")]
        [TestCase("<saml:EncryptedAssertion/><saml:EncryptedAssertion/>")]
        public void ResponseWithoutExactlyOneEncryptedAssertionIsRejected(string content)
        {
            var e = Assert.Throws<Saml20Exception>(() => Saml20SignonHandler.GetEncryptedAssertion(Response(content)));
            StringAssert.Contains("[OIO-IDP-11]", e.Message);
        }
    }
}
