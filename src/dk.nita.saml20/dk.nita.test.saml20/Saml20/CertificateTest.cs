using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using dk.nita.saml20.config;
using NUnit.Framework;

namespace dk.nita.test.Saml20
{
    [TestFixture]
    public class CertificateTest
    {
        private static X509Certificate2 Create(int notBeforeDays, int notAfterDays)
        {
            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return request.CreateSelfSigned(DateTimeOffset.Now.AddDays(notBeforeDays), DateTimeOffset.Now.AddDays(notAfterDays));
            }
        }

        private static Certificate Found(Func<X509Certificate2[]> find)
        {
            return new Certificate { FindInStore = () => new X509Certificate2Collection(find()) };
        }

        [Test]
        public void ValidCertificateWithTheLatestNotBeforeIsUsed()
        {
            var older = Create(-10, 100);
            var newer = Create(-1, 100);
            var notYetValid = Create(1, 100);
            var expired = Create(-20, -1);
            var certificate = Found(() => new[] { older, notYetValid, newer, expired });

            Assert.AreEqual(newer.Thumbprint, certificate.GetFirstValidX509Certificate().Thumbprint);
            CollectionAssert.AreEqual(new[] { newer.Thumbprint, older.Thumbprint },
                certificate.GetAllValidX509Certificates().Cast<X509Certificate2>().Select(c => c.Thumbprint));
        }

        [Test]
        public void MetadataPublishesEveryUnexpiredCertificate()
        {
            var current = Create(-10, 100);
            var next = Create(1, 100);
            var expired = Create(-20, -1);
            var certificate = Found(() => new[] { current, next, expired });

            CollectionAssert.AreEqual(new[] { next.Thumbprint, current.Thumbprint },
                certificate.GetUnexpiredX509Certificates().Cast<X509Certificate2>().Select(c => c.Thumbprint));
        }

        [Test]
        public void CertificateWithoutPrivateKeyIsNotUsed()
        {
            var withKey = Create(-10, 100);
            var publicOnly = new X509Certificate2(Create(-1, 100).Export(X509ContentType.Cert));
            var certificate = Found(() => new[] { publicOnly, withKey });

            Assert.AreEqual(withKey.Thumbprint, certificate.GetFirstValidX509Certificate().Thumbprint);
        }

        [Test]
        public void NoValidCertificateGivesNull()
        {
            var certificate = Found(() => new[] { Create(-20, -1) });

            Assert.IsNull(certificate.GetFirstValidX509Certificate());
            Assert.IsNull(certificate.GetAllValidX509Certificates());
        }

        [Test]
        public void StoreIsSearchedAgainOnlyAfterTheRefreshInterval()
        {
            var searches = 0;
            var valid = Create(-1, 100);
            var certificate = Found(() => { searches++; return new[] { valid }; });

            certificate.GetFirstValidX509Certificate();
            certificate.GetAllValidX509Certificates();
            Assert.AreEqual(1, searches);

            certificate.RefreshInterval = TimeSpan.Zero;
            certificate.GetFirstValidX509Certificate();
            Assert.AreEqual(2, searches);
        }

        [Test]
        public void CertificateInstalledAfterAnEmptySearchIsFound()
        {
            var installed = new X509Certificate2[0];
            var certificate = Found(() => installed);
            Assert.IsNull(certificate.GetFirstValidX509Certificate());

            var valid = Create(-1, 100);
            installed = new[] { valid };
            Assert.AreEqual(valid.Thumbprint, certificate.GetFirstValidX509Certificate().Thumbprint);
        }

        [Test]
        public void ChainIsNotValidatedEvenWithValidOnly()
        {
            // Self-signed, so the chain can't be validated.
            var selfSigned = new X509Certificate2(Create(-1, 100).Export(X509ContentType.Pfx), (string)null,
                X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            try
            {
                store.Add(selfSigned);
                Certificate Configured(bool validOnly) => new Certificate
                {
                    storeName = StoreName.My,
                    storeLocation = StoreLocation.CurrentUser,
                    x509FindType = X509FindType.FindByThumbprint,
                    findValue = selfSigned.Thumbprint,
                    validOnly = validOnly
                };

                Assert.AreEqual(selfSigned.Thumbprint, Configured(false).GetFirstValidX509Certificate().Thumbprint);
                Assert.AreEqual(selfSigned.Thumbprint, Configured(true).GetFirstValidX509Certificate().Thumbprint);
                Assert.AreEqual(selfSigned.Thumbprint, Configured(true).GetCertificate().Thumbprint);
            }
            finally
            {
                store.Remove(selfSigned);
                store.Close();
                if (selfSigned.GetRSAPrivateKey() is RSACng cng)
                    cng.Key.Delete();
                else if (selfSigned.GetRSAPrivateKey() is RSACryptoServiceProvider csp)
                {
                    csp.PersistKeyInCsp = false;
                    csp.Clear();
                }
            }
        }
    }
}
