using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha256SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA256Url;
        public override string DigestUri => SignedXml.XmlDsigSHA256Url;
        protected override HashAlgorithmName HashName => HashAlgorithmName.SHA256;
    }
}