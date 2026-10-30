using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using dk.nita.saml20;
using dk.nita.saml20.config;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Utils;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class MetadataReloadTest
    {
        private const string IdpEntityId = "https://idp.example.dk";
        private string _directory;
        private IDPEndpoints _endpoints;

        [SetUp]
        public void CreateMetadataDirectory()
        {
            _directory = Path.Combine(Path.GetTempPath(), "oiosaml-metadata-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_directory);
            _endpoints = new IDPEndpoints { MetadataLocation = _directory };
            _endpoints.IDPEndPoints.Add(new IDPEndPoint { Id = IdpEntityId, Name = "NemLog-in" });
        }

        [TearDown]
        public void DeleteMetadataDirectory()
        {
            Directory.Delete(_directory, true);
        }

        private static string Certificate()
        {
            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using (var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)))
                    return Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
            }
        }

        private static string Metadata(string entityId, params string[] keyDescriptors)
        {
            return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"" + entityId + "\">" +
                   "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
                   string.Concat(keyDescriptors) +
                   "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + entityId + "/sso\"/>" +
                   "</md:IDPSSODescriptor></md:EntityDescriptor>";
        }

        private static string Key(string use, string certificate)
        {
            var useAttribute = use == null ? "" : " use=\"" + use + "\"";
            return "<md:KeyDescriptor" + useAttribute + "><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + certificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
        }

        private string Write(string name, string content, int ageSeconds = 0)
        {
            var file = Path.Combine(_directory, name);
            File.WriteAllText(file, content);
            File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddSeconds(-ageSeconds));
            return file;
        }

        private IDPEndPoint Idp(string id = IdpEntityId)
        {
            return _endpoints.IDPEndPoints.SingleOrDefault(e => e.Id == id);
        }

        [Test]
        public void ConfiguredEndpointGetsItsMetadata()
        {
            Write("nemlogin.xml", Metadata(IdpEntityId, Key("signing", Certificate())));

            Assert.IsTrue(_endpoints.LoadMetadata());

            Assert.AreEqual("NemLog-in", Idp().Name);
            Assert.AreEqual(1, Idp().metadata.GetKeys(KeyTypes.signing).Count);
        }

        [Test]
        public void ReplacingTheFileWithANewOneKeepsTheEndpoint()
        {
            var old = Write("nemlogin-old.xml", Metadata(IdpEntityId, Key("signing", Certificate())));
            _endpoints.LoadMetadata();

            var newCertificate = Certificate();
            Write("nemlogin-new.xml", Metadata(IdpEntityId, Key("signing", newCertificate)));
            File.Delete(old);
            _endpoints.LoadMetadata();

            Assert.IsNotNull(Idp().metadata);
            Assert.AreEqual("NemLog-in", Idp().Name);
            Assert.AreEqual(newCertificate, CertificateOf(Idp().metadata.GetKeys(KeyTypes.signing).Single()));
        }

        [Test]
        public void KeysOfAllFilesForAnEntityAreTrusted()
        {
            Write("nemlogin-old.xml", Metadata(IdpEntityId, Key("signing", Certificate())), ageSeconds: 60);
            Write("nemlogin-new.xml", Metadata(IdpEntityId, Key("signing", Certificate())));

            _endpoints.LoadMetadata();

            Assert.AreEqual(2, Idp().metadata.GetKeys(KeyTypes.signing).Count);
            Assert.AreEqual(1, _endpoints.IDPEndPoints.Count);
        }

        [Test]
        public void ReloadingDoesNotAddKeysAgain()
        {
            Write("nemlogin-old.xml", Metadata(IdpEntityId, Key("signing", Certificate())), ageSeconds: 60);
            Write("nemlogin-new.xml", Metadata(IdpEntityId, Key("signing", Certificate())));

            _endpoints.LoadMetadata();
            _endpoints.LoadMetadata();

            Assert.AreEqual(2, Idp().metadata.GetKeys(KeyTypes.signing).Count);
        }

        [Test]
        public void ConfiguredEndpointIsKeptWithoutMetadataWhenItsFileIsDeleted()
        {
            var file = Write("nemlogin.xml", Metadata(IdpEntityId, Key("signing", Certificate())));
            _endpoints.LoadMetadata();

            File.Delete(file);
            _endpoints.LoadMetadata();

            Assert.IsNotNull(Idp());
            Assert.IsNull(Idp().metadata);
        }

        [Test]
        public void EndpointFromAMetadataFileGoesWithTheFile()
        {
            var file = Write("other.xml", Metadata("https://other.example.dk", Key("signing", Certificate())));
            _endpoints.LoadMetadata();
            Assert.IsNotNull(Idp("https://other.example.dk"));

            File.Delete(file);
            _endpoints.LoadMetadata();

            Assert.IsNull(Idp("https://other.example.dk"));
            Assert.IsNotNull(Idp());
        }

        [Test]
        public void FileThatIsNotMetadataIsIgnored()
        {
            Write("README.txt", "Put the IdP metadata here.");
            Write("nemlogin.xml", Metadata(IdpEntityId, Key("signing", Certificate())));

            Assert.IsTrue(_endpoints.LoadMetadata());

            Assert.AreEqual(1, _endpoints.IDPEndPoints.Count);
            Assert.IsNotNull(Idp().metadata);
        }

        [Test]
        public void HalfWrittenFileKeepsItsLastVersion()
        {
            var file = Write("nemlogin.xml", Metadata(IdpEntityId, Key("signing", Certificate())));
            _endpoints.LoadMetadata();

            File.WriteAllText(file, "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + IdpEntityId);

            Assert.IsFalse(_endpoints.LoadMetadata());
            Assert.AreEqual(1, Idp().metadata.GetKeys(KeyTypes.signing).Count);
        }

        [Test]
        public void LockedFileKeepsItsLastVersion()
        {
            var file = Write("nemlogin.xml", Metadata(IdpEntityId, Key("signing", Certificate())));
            _endpoints.LoadMetadata();

            using (new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Assert.IsFalse(_endpoints.LoadMetadata());
            }

            Assert.IsNotNull(Idp().metadata);
            Assert.IsTrue(_endpoints.LoadMetadata());
        }

        [Test]
        public void EndpointListIsReplacedNotChanged()
        {
            Write("nemlogin.xml", Metadata(IdpEntityId, Key("signing", Certificate())));
            var before = _endpoints.IDPEndPoints;

            _endpoints.LoadMetadata();

            Assert.AreNotSame(before, _endpoints.IDPEndPoints);
            Assert.AreEqual(1, before.Count);
        }

        [Test]
        public void FileWatcherReloadsAfterAKeyRotation()
        {
            var old = Write("nemlogin-old.xml", Metadata(IdpEntityId, Key("signing", Certificate())));
            _endpoints.Initialize();
            var oldMetadata = Idp().metadata;

            var newCertificate = Certificate();
            Write("nemlogin-new.xml", Metadata(IdpEntityId, Key("signing", newCertificate)));
            File.Delete(old);

            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (ReferenceEquals(Idp().metadata, oldMetadata) && DateTime.UtcNow < deadline)
                Thread.Sleep(100);

            Assert.AreNotSame(oldMetadata, Idp().metadata, "The file watcher did not reload the metadata.");
            Assert.AreEqual(newCertificate, CertificateOf(Idp().metadata.GetKeys(KeyTypes.signing).Single()));
        }

        [TestCase("signing", 1)]
        [TestCase(null, 1)]
        [TestCase("encryption", 0)]
        public void KeyWithoutUseIsASigningKey(string use, int signingKeys)
        {
            Write("nemlogin.xml", Metadata(IdpEntityId, Key(use, Certificate())));

            _endpoints.LoadMetadata();

            Assert.AreEqual(signingKeys, Idp().metadata.GetKeys(KeyTypes.signing).Count);
        }

        [Test]
        public void KeyWithoutUseIsAlsoAnEncryptionKey()
        {
            Write("nemlogin.xml", Metadata(IdpEntityId, Key(null, Certificate())));

            _endpoints.LoadMetadata();

            Assert.AreEqual(1, Idp().metadata.GetKeys(KeyTypes.encryption).Count);
        }

        [Test]
        public void UnreadableFileLosesItsLastVersionAfterTheGracePeriod()
        {
            var file = Write("nemlogin.xml", Metadata(IdpEntityId, Key("signing", Certificate())));
            _endpoints.LoadMetadata();
            _endpoints.UnreadableGracePeriod = TimeSpan.Zero;

            File.WriteAllText(file, "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + IdpEntityId);

            Assert.IsFalse(_endpoints.LoadMetadata());
            Assert.IsNull(Idp().metadata);
        }

        [Test]
        public void FileThatIsReadableButNotUsableMetadataLosesItsLastVersion()
        {
            var file = Write("nemlogin.xml", Metadata(IdpEntityId, Key("signing", Certificate())));
            _endpoints.LoadMetadata();

            File.WriteAllText(file, "<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">" + Metadata(IdpEntityId, Key("signing", Certificate())) + "</md:EntitiesDescriptor>");

            Assert.IsTrue(_endpoints.LoadMetadata());
            Assert.IsNull(Idp().metadata);
        }

        [Test]
        public void FileThatCantBeReadAtStartupIsRetried()
        {
            var file = Write("nemlogin.xml", "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + IdpEntityId);

            Assert.IsFalse(_endpoints.LoadMetadata());
            Assert.IsNull(Idp().metadata);

            File.WriteAllText(file, Metadata(IdpEntityId, Key("signing", Certificate())));

            Assert.IsTrue(_endpoints.LoadMetadata());
            Assert.IsNotNull(Idp().metadata);
        }

        [TestCase("signing")]
        [TestCase(null)]
        public void SignatureWithTheCertificateOfASecondFileIsVerified(string use)
        {
            using (var newKey = RSA.Create(2048))
            {
                Write("nemlogin-old.xml", Metadata(IdpEntityId, Key("signing", Certificate())), ageSeconds: 60);
                Write("nemlogin-new.xml", Metadata(IdpEntityId, Key(use, Certificate(newKey))));
                _endpoints.LoadMetadata();

                var signed = Sign(newKey);

                var verifiedBy = Idp().metadata.GetKeys(KeyTypes.signing)
                    .SelectMany(key => ((System.Security.Cryptography.Xml.KeyInfo)key.KeyInfo).Cast<System.Security.Cryptography.Xml.KeyInfoClause>())
                    .Count(clause => XmlSignatureUtils.CheckSignature(signed, XmlSignatureUtils.ExtractKey(clause)));
                Assert.AreEqual(1, verifiedBy);
            }
        }

        private static string Certificate(RSA key)
        {
            var request = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using (var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)))
                return Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
        }

        private static System.Xml.XmlElement Sign(RSA key)
        {
            var document = new System.Xml.XmlDocument { PreserveWhitespace = true };
            document.LoadXml("<Message ID=\"_message\">signed by the new key</Message>");
            var signedXml = new System.Security.Cryptography.Xml.SignedXml(document.DocumentElement) { SigningKey = key };
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            signedXml.SignedInfo.CanonicalizationMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigExcC14NTransformUrl;
            var reference = new System.Security.Cryptography.Xml.Reference("#_message") { DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256" };
            reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);
            signedXml.ComputeSignature();
            document.DocumentElement.AppendChild(document.ImportNode(signedXml.GetXml(), true));
            return document.DocumentElement;
        }

        private static string CertificateOf(KeyDescriptor key)
        {
            var keyInfo = (System.Security.Cryptography.Xml.KeyInfo)key.KeyInfo;
            foreach (var clause in keyInfo)
            {
                if (clause is System.Security.Cryptography.Xml.KeyInfoX509Data data)
                    return Convert.ToBase64String(((X509Certificate)data.Certificates[0]).GetRawCertData());
            }
            return null;
        }
    }
}
