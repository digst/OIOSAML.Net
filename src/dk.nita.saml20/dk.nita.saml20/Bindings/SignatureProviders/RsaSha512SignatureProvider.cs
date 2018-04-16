using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha512SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA512Url;
        public override string DigestUri => SignedXml.XmlDsigSHA512Url;
        public override byte[] SignData(AsymmetricAlgorithm key, byte[] data)
        {
            var rsa = (RSACryptoServiceProvider)key;
            return rsa.SignData(data, new SHA512CryptoServiceProvider());
        }

        public override bool VerifySignature(AsymmetricAlgorithm key, byte[] data, byte[] signature)
        {
            var hash = new SHA512Managed().ComputeHash(data);
            return ((RSACryptoServiceProvider)key).VerifyHash(hash, "SHA512", signature);
        }
    }
}