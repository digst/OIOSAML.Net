using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha512SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA512Url;
        public override string DigestUri => SignedXml.XmlDsigSHA512Url;
        protected override HashAlgorithmName HashName => HashAlgorithmName.SHA512;
    }
}