using System.Collections.Generic;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.protocol;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class SoapLogoutRequestTest
    {
        private readonly List<string> _audit = new List<string>();
        private readonly List<string> _loggedOut = new List<string>();

        [SetUp]
        public void Clear()
        {
            _audit.Clear();
            _loggedOut.Clear();
        }

        private (string StatusCode, string SubStatusCode) Handle(bool isSigned = true, bool isIdpKnown = true, bool isSignatureValid = true, bool isExpired = false, string userId = "user")
        {
            return Saml20LogoutHandler.HandleSoapLogoutRequest(isSigned, isIdpKnown, () => isSignatureValid, () => isExpired, userId, _loggedOut.Add, _audit.Add);
        }

        private static readonly (string, string) Denied = (Saml20Constants.StatusCodes.Requester, Saml20Constants.StatusCodes.RequestDenied);

        [Test]
        public void ValidRequestLogsTheUserOut()
        {
            Assert.AreEqual((Saml20Constants.StatusCodes.Success, (string)null), Handle());
            CollectionAssert.AreEqual(new[] { "user" }, _loggedOut);
            Assert.IsEmpty(_audit);
        }

        [Test]
        public void UnsignedRequestIsDenied()
        {
            Assert.AreEqual(Denied, Handle(isSigned: false));
            Assert.IsEmpty(_loggedOut);
            Assert.AreEqual(1, _audit.Count);
        }

        [Test]
        public void RequestFromUnknownIdpIsDenied()
        {
            Assert.AreEqual(Denied, Handle(isIdpKnown: false));
            Assert.IsEmpty(_loggedOut);
        }

        [Test]
        public void RequestWithInvalidSignatureIsDenied()
        {
            Assert.AreEqual(Denied, Handle(isSignatureValid: false));
            Assert.IsEmpty(_loggedOut);
        }

        [Test]
        public void ExpiredRequestIsDenied()
        {
            Assert.AreEqual(Denied, Handle(isExpired: true));
            Assert.IsEmpty(_loggedOut);
        }

        [TestCase(null)]
        [TestCase("")]
        public void RequestWithoutUserIdIsDeniedAsUnknownPrincipal(string userId)
        {
            Assert.AreEqual((Saml20Constants.StatusCodes.Requester, Saml20Constants.StatusCodes.UnknownPrincipal), Handle(userId: userId));
            Assert.IsEmpty(_loggedOut);
        }

        [Test]
        public void SignatureIsNotCheckedForUnsignedRequestOrUnknownIdp()
        {
            var checkedSignature = false;
            Saml20LogoutHandler.HandleSoapLogoutRequest(false, true, () => checkedSignature = true, () => false, "user", _loggedOut.Add, _audit.Add);
            Saml20LogoutHandler.HandleSoapLogoutRequest(true, false, () => checkedSignature = true, () => false, "user", _loggedOut.Add, _audit.Add);
            Assert.IsFalse(checkedSignature, "The signature check reads the IdP's metadata, which an unknown IdP doesn't have.");
        }

        [Test]
        public void ExpiryIsCheckedOnlyAfterTheSignature()
        {
            var checkedExpiry = false;
            Saml20LogoutHandler.HandleSoapLogoutRequest(true, true, () => false, () => checkedExpiry = true, "user", _loggedOut.Add, _audit.Add);
            Assert.IsFalse(checkedExpiry);
        }

        [Test]
        public void DenialIsTopLevelRequesterWithTheReasonBelow()
        {
            var response = new Saml20LogoutResponse { StatusCode = Saml20Constants.StatusCodes.Requester, SubStatusCode = Saml20Constants.StatusCodes.RequestDenied };

            var xml = response.GetXml();
            var codes = xml.GetElementsByTagName("StatusCode", Saml20Constants.PROTOCOL);
            Assert.AreEqual(2, codes.Count);
            Assert.AreEqual(Saml20Constants.StatusCodes.Requester, ((XmlElement)codes[0]).GetAttribute("Value"));
            Assert.AreEqual(Saml20Constants.StatusCodes.RequestDenied, ((XmlElement)codes[1]).GetAttribute("Value"));
            Assert.AreSame(codes[0], codes[1].ParentNode);
        }

        [Test]
        public void SuccessHasNoSecondLevelStatus()
        {
            var response = new Saml20LogoutResponse { StatusCode = Saml20Constants.StatusCodes.Success };

            Assert.AreEqual(1, response.GetXml().GetElementsByTagName("StatusCode", Saml20Constants.PROTOCOL).Count);
            Assert.IsNull(response.SubStatusCode);
        }
    }
}
