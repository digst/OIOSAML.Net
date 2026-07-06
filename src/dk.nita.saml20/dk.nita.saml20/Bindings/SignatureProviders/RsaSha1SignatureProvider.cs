using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha1SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA1Url;
        public override string DigestUri => SignedXml.XmlDsigSHA1Url;
        protected override HashAlgorithmName HashName => HashAlgorithmName.SHA1;

    }
}