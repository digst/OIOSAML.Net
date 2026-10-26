using System;
using System.Collections.Generic;
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
        private static readonly ICollection<Uri> Acs = new List<Uri> { new Uri("https://sp.example.dk:20002/login.ashx") };

        private static Assertion AssertionWith(params SubjectConfirmation[] confirmations)
        {
            var items = new List<object> { new NameID { Value = "user" } };
            items.AddRange(confirmations);
            return new Assertion { Subject = new Subject { Items = items.ToArray() } };
        }

        private static SubjectConfirmation Bearer(string inResponseTo, string recipient, string method = SubjectConfirmation.BEARER_METHOD)
        {
            return new SubjectConfirmation
            {
                Method = method,
                SubjectConfirmationData = new SubjectConfirmationData { InResponseTo = inResponseTo, Recipient = recipient }
            };
        }

        [Test]
        public void BearerConfirmationAnsweringTheRequestIsAccepted()
        {
            Assert.IsNull(Saml20SignonHandler.CheckBearerConfirmation(AssertionWith(Bearer(RequestId, "https://sp.example.dk:20002/login.ashx")), RequestId, Acs));
        }

        [Test]
        public void RecipientIsComparedAsAUrl()
        {
            Assert.IsNull(Saml20SignonHandler.CheckBearerConfirmation(AssertionWith(Bearer(RequestId, "https://SP.example.dk:20002/login.ashx")), RequestId, Acs));
        }

        [TestCase("idOtherRequest")]
        [TestCase(null)]
        public void BearerConfirmationForAnotherRequestIsRejected(string inResponseTo)
        {
            Assert.IsNotNull(Saml20SignonHandler.CheckBearerConfirmation(AssertionWith(Bearer(inResponseTo, "https://sp.example.dk:20002/login.ashx")), RequestId, Acs));
        }

        [TestCase(null)]
        [TestCase("")]
        public void MissingExpectedRequestIsRejected(string expectedRequestId)
        {
            Assert.IsNotNull(Saml20SignonHandler.CheckBearerConfirmation(AssertionWith(Bearer(expectedRequestId, "https://sp.example.dk:20002/login.ashx")), expectedRequestId, Acs));
        }

        [TestCase("https://other.example.dk/login.ashx")]
        [TestCase("https://sp.example.dk:20002/logout.ashx")]
        [TestCase("https://sp.example.dk")]
        [TestCase("not a url")]
        [TestCase(null)]
        public void RecipientOtherThanTheAcsIsRejected(string recipient)
        {
            Assert.IsNotNull(Saml20SignonHandler.CheckBearerConfirmation(AssertionWith(Bearer(RequestId, recipient)), RequestId, Acs));
        }

        [Test]
        public void NonBearerConfirmationIsIgnored()
        {
            var holderOfKey = Bearer(RequestId, "https://sp.example.dk:20002/login.ashx", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
            Assert.IsNotNull(Saml20SignonHandler.CheckBearerConfirmation(AssertionWith(holderOfKey), RequestId, Acs));
        }

        [Test]
        public void InResponseToAndRecipientMustBeInTheSameConfirmation()
        {
            var assertion = AssertionWith(Bearer(RequestId, "https://other.example.dk/login.ashx"), Bearer("idOtherRequest", "https://sp.example.dk:20002/login.ashx"));
            Assert.IsNotNull(Saml20SignonHandler.CheckBearerConfirmation(assertion, RequestId, Acs));
        }

        [Test]
        public void OneMatchingBearerConfirmationIsEnough()
        {
            var assertion = AssertionWith(Bearer("idOtherRequest", "https://other.example.dk/login.ashx"), Bearer(RequestId, "https://sp.example.dk:20002/login.ashx"));
            Assert.IsNull(Saml20SignonHandler.CheckBearerConfirmation(assertion, RequestId, Acs));
        }

        [Test]
        public void AssertionWithoutSubjectIsRejected()
        {
            Assert.IsNotNull(Saml20SignonHandler.CheckBearerConfirmation(new Assertion(), RequestId, Acs));
        }

        [Test]
        public void AssertionConsumerServiceUrlsAreTheSignOnEndpoints()
        {
            var serviceProvider = new ServiceProviderElement
            {
                Server = "https://sp.example.dk:20002",
                serviceEndpoints = new List<Saml20ServiceEndpoint>
                {
                    new Saml20ServiceEndpoint { endpointType = EndpointType.SIGNON, localPath = "/login.ashx" },
                    new Saml20ServiceEndpoint { endpointType = EndpointType.LOGOUT, localPath = "/logout.ashx" },
                }
            };

            CollectionAssert.AreEqual(new[] { new Uri("https://sp.example.dk:20002/login.ashx") }, Saml20SignonHandler.AssertionConsumerServiceUrls(serviceProvider));
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
            Assert.Throws<Saml20Exception>(() => Saml20SignonHandler.GetEncryptedAssertion(Response(content)));
        }
    }
}
