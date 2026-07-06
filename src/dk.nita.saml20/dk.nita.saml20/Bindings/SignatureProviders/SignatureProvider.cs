using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Trace = dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal abstract class SignatureProvider : ISignatureProvider
    {
        public abstract string SignatureUri { get; }

        public abstract string DigestUri { get; }

        public byte[] SignData(AsymmetricAlgorithm key, byte[] data)
        {
            var rsa = ToSha2CapableRsa(key);

            return rsa.SignData(data, HashName, RSASignaturePadding.Pkcs1);
        }

        public bool VerifySignature(AsymmetricAlgorithm key, byte[] data, byte[] signature)
        {
            var rsa = ToSha2CapableRsa(key);

            return rsa.VerifyData(data, signature, HashName, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// The hash algorithm this provider uses when signing/verifying raw data such as the HTTP-Redirect query.
        /// </summary>
        protected abstract HashAlgorithmName HashName { get; }

        public void SignAssertion(XmlDocument doc, string id, X509Certificate2 cert)
        {
            var signedXml = Sign(doc, id, cert);
            // Append the computed signature. The signature must be placed as the sibling of the Issuer element.
            XmlNodeList nodes = doc.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            nodes[0].ParentNode.InsertAfter(doc.ImportNode(signedXml.GetXml(), true), nodes[0]);
        }

        public void SignMetaData(XmlDocument doc, string id, X509Certificate2 cert)
        {
            var signedXml = Sign(doc, id, cert);
            doc.DocumentElement.InsertBefore(doc.ImportNode(signedXml.GetXml(), true), doc.DocumentElement.FirstChild);
        }
        private SignedXml Sign(XmlDocument doc, string id, X509Certificate2 cert)
        {
            SignedXml signedXml = new SignedXml(doc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignatureUri;
            signedXml.SigningKey = cert.GetRSAPrivateKey();

            // Retrieve the value of the "ID" attribute on the root assertion element.
            Reference reference = new Reference("#" + id);
            reference.DigestMethod = DigestUri;

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);

            // Include the public key of the certificate in the assertion.
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.WholeChain));

            signedXml.ComputeSignature();
            return signedXml;
        }

        /// <summary>
        /// Returns an <see cref="RSA"/> instance guaranteed to support SHA-2, keeping the signing/verification
        /// path provider-agnostic: it works with modern CNG keys (<see cref="RSACng"/>) as well as legacy
        /// CryptoAPI keys (<see cref="RSACryptoServiceProvider"/>).
        /// </summary>
        private static RSA ToSha2CapableRsa(AsymmetricAlgorithm key)
        {
            var rsa = (RSA)key;

            // CNG keys already support SHA-2.
            if (rsa is RSACng)
                return rsa;

            var csp = rsa as RSACryptoServiceProvider;
            if (csp == null)
                return rsa;

            // Public keys (inbound signature verification): re-import into a CNG key, which supports
            // SHA-2 regardless of the originating CSP provider type.
            if (csp.PublicOnly)
            {
                var cng = new RSACng();
                cng.ImportParameters(csp.ExportParameters(false));
                return cng;
            }

            // A private key backed by a legacy PROV_RSA_FULL (provider type 1) CSP only supports SHA-1.
            // Reopen the same key container under PROV_RSA_AES (provider type 24), which supports SHA-2.
            // https://github.com/Microsoft/referencesource/blob/master/System.IdentityModel/System/IdentityModel/Tokens/X509AsymmetricSecurityKey.cs#L54
            if (csp.CspKeyContainerInfo.ProviderType == 1)
            {
                if (Trace.ShouldTrace(TraceEventType.Verbose))
                    Trace.TraceData(TraceEventType.Verbose, "Reopened RSA private key under provider type 24 to enable SHA-2");

                var cspParams = new CspParameters
                {
                    ProviderType = 24,
                    KeyContainerName = csp.CspKeyContainerInfo.KeyContainerName,
                    KeyNumber = (int)csp.CspKeyContainerInfo.KeyNumber
                };
                if (csp.CspKeyContainerInfo.MachineKeyStore)
                    cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
                cspParams.Flags |= CspProviderFlags.UseExistingKey;
                return new RSACryptoServiceProvider(cspParams);
            }

            return rsa;
        }
    }
}