using System.Collections.Generic;
using dk.nita.saml20;
using dk.nita.saml20.protocol;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class SoapLogoutRequestTest
    {
        private readonly List<string> _audit = new List<string>();

        [SetUp]
        public void ClearAudit()
        {
            _audit.Clear();
        }

        private string Status(bool isSigned, bool isIdpKnown, bool isSignatureValid, string userId)
        {
            return Saml20LogoutHandler.SoapLogoutRequestStatus(isSigned, isIdpKnown, () => isSignatureValid, userId, _audit.Add);
        }

        [Test]
        public void ValidRequestIsAccepted()
        {
            Assert.AreEqual(Saml20Constants.StatusCodes.Success, Status(true, true, true, "user"));
            Assert.IsEmpty(_audit);
        }

        [Test]
        public void UnsignedRequestIsDenied()
        {
            Assert.AreEqual(Saml20Constants.StatusCodes.RequestDenied, Status(false, true, true, "user"));
            Assert.AreEqual(1, _audit.Count);
        }

        [Test]
        public void RequestWithInvalidSignatureIsDenied()
        {
            Assert.AreEqual(Saml20Constants.StatusCodes.RequestDenied, Status(true, true, false, "user"));
            Assert.AreEqual(1, _audit.Count);
        }

        [Test]
        public void RequestFromUnknownIdpIsDenied()
        {
            Assert.AreEqual(Saml20Constants.StatusCodes.NoAvailableIDP, Status(true, false, true, "user"));
        }

        [Test]
        public void SignatureIsNotCheckedForUnsignedRequest()
        {
            var checkedSignature = false;
            Saml20LogoutHandler.SoapLogoutRequestStatus(false, true, () => checkedSignature = true, "user", _audit.Add);
            Assert.IsFalse(checkedSignature);
        }

        [TestCase(null)]
        [TestCase("")]
        public void RequestWithoutUserIdIsDenied(string userId)
        {
            Assert.AreEqual(Saml20Constants.StatusCodes.NoAuthnContext, Status(true, true, true, userId));
        }
    }
}
