using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha256SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA256Url;
        public override string DigestUri => SignedXml.XmlDsigSHA256Url;
        protected override byte[] SignDataIntern(RSACryptoServiceProvider key, byte[] data)
        {
            return key.SignData(data, new SHA256CryptoServiceProvider());
        }

        protected override bool VerifySignatureIntern(RSACryptoServiceProvider key, byte[] data, byte[] signature)
        {
            var hash = new SHA256Managed().ComputeHash(data);
            return ((RSACryptoServiceProvider)key).VerifyHash(hash, "SHA256", signature);
        }
    }
}