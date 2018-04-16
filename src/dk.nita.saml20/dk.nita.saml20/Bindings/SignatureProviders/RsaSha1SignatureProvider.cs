using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha1SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA1Url;
        public override string DigestUri => SignedXml.XmlDsigSHA1Url;
        public override byte[] SignData(AsymmetricAlgorithm key, byte[] data)
        {
            var rsa = (RSACryptoServiceProvider) key;
            return rsa.SignData(data, new SHA1CryptoServiceProvider());
        }

        public override bool VerifySignature(AsymmetricAlgorithm key, byte[] data, byte[] signature)
        {
            var hash = new SHA1Managed().ComputeHash(data);
            return ((RSACryptoServiceProvider) key).VerifyHash(hash, "SHA1", signature);
        }

    }
}