using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha256SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA256Url;
        public override string DigestUri => SignedXml.XmlDsigSHA256Url;
        public override byte[] SignData(AsymmetricAlgorithm key, byte[] data)
        {
            var rsa = (RSACryptoServiceProvider)key;
            return rsa.SignData(data, new SHA256CryptoServiceProvider());
        }

        public override bool VerifySignature(AsymmetricAlgorithm key, byte[] data, byte[] signature)
        {
            var hash = new SHA256Managed().ComputeHash(data);
            return ((RSACryptoServiceProvider)key).VerifyHash(hash, "SHA256", signature);
        }
    }
}