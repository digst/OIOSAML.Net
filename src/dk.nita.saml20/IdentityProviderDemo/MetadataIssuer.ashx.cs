using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Utils;
using IdentityProviderDemo.Logic;

namespace IdentityProviderDemo
{
    /// <summary>
    /// Generates a signed metadata file.
    /// </summary>
    public class MetadataIssuer : IHttpHandler
    {

        public void ProcessRequest(HttpContext context)
        {
            context.Response.ContentType = "text/xml";
            context.Response.AddHeader("Content-Disposition", "attachment; filename=\"metadata.xml\"");

            GenerateMetadataDocument(context);
        }

        private void GenerateMetadataDocument(HttpContext context)
        {
            EntityDescriptor metadata = new EntityDescriptor();
            metadata.entityID = IDPConfig.ServerBaseUrl;
            metadata.ID = "id" + Guid.NewGuid().ToString("N");

            IDPSSODescriptor descriptor = new IDPSSODescriptor();
            metadata.Items = new object[] { descriptor };
            descriptor.protocolSupportEnumeration = new string[] { Saml20Constants.PROTOCOL };
            descriptor.KeyDescriptor = CreateKeyDescriptors();
            
            { // Signon endpoint
                Endpoint endpoint = new Endpoint();
                endpoint.Location = IDPConfig.ServerBaseUrl + "Signon.ashx";
                endpoint.Binding = Saml20Constants.ProtocolBindings.HTTP_Redirect;
                descriptor.SingleSignOnService = new Endpoint[] { endpoint };
            }

            { // Logout endpoint
                Endpoint endpoint = new Endpoint();
                endpoint.Location = IDPConfig.ServerBaseUrl + "Logout.ashx";
                endpoint.Binding = Saml20Constants.ProtocolBindings.HTTP_Redirect;
                descriptor.SingleLogoutService = new Endpoint[] { endpoint };
            }

            // Create the list of attributes offered.
            List<SamlAttribute> atts = new List<SamlAttribute>(IDPConfig.attributes.Length);
            foreach (string name in IDPConfig.attributes)
            {
                SamlAttribute att = new SamlAttribute();
                att.NameFormat = SamlAttribute.NAMEFORMAT_BASIC;
                att.Name = name;
                atts.Add(att);
            }

            descriptor.Attributes = atts.ToArray();
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.LoadXml(Serialization.SerializeToXmlString(metadata));

            signDocument(doc);

            context.Response.Write( doc.OuterXml );
        }

        /// <summary>
        /// Creates the necessary key descriptors for the metadata based on the certificate in the IDPConfig class.
        /// </summary>
        /// <returns></returns>
        private static KeyDescriptor[] CreateKeyDescriptors()
        {
            List<KeyDescriptor> keys = new List<KeyDescriptor>();

            // Pack the certificate.
            KeyInfo keyinfo = new KeyInfo();
            KeyInfoX509Data keyClause = new KeyInfoX509Data(IDPConfig.IDPCertificate, X509IncludeOption.EndCertOnly);
            keyinfo.AddClause(keyClause);
            
            { // Create signing key element.
                KeyDescriptor key = new KeyDescriptor();
                keys.Add(key);
                key.use = KeyTypes.signing;
                key.useSpecified = true;
                key.KeyInfo = Serialization.DeserializeFromXmlString<dk.nita.saml20.Schema.XmlDSig.KeyInfo>(keyinfo.GetXml().OuterXml);
            }

            { // Create encryption key element
                KeyDescriptor key = new KeyDescriptor();
                keys.Add(key);
                key.use = KeyTypes.encryption;
                key.useSpecified = true;
                key.KeyInfo = Serialization.DeserializeFromXmlString<dk.nita.saml20.Schema.XmlDSig.KeyInfo>(keyinfo.GetXml().OuterXml);
            }

            return keys.ToArray();
        }

        /// <summary>
        /// Mostly nicked from the dk.nita.saml20.Saml20MetadataDocument class. 
        /// </summary>
        private static void signDocument(XmlDocument doc)
        {
            X509Certificate2 cert = IDPConfig.IDPCertificate;

            // We already checked for this when the certificate was selected, but dual-checking almost never hurts.
            if (!cert.HasPrivateKey) 
                throw new InvalidOperationException("Private key access to the signing certificate is required.");

            SignedXml signedXml = new SignedXml(doc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SigningKey = cert.PrivateKey;

            // Retrieve the value of the "ID" attribute on the root assertion element.                        
            Reference reference = new Reference("#" + doc.DocumentElement.GetAttribute("ID"));

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);

            // Include the public key of the certificate in the assertion.
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.WholeChain));

            signedXml.ComputeSignature();
            // Append the computed signature. The signature must be placed as the sibling of the Issuer element.            
            doc.DocumentElement.InsertBefore(doc.ImportNode(signedXml.GetXml(), true), doc.DocumentElement.FirstChild);
        }    

        public bool IsReusable
        {
            get
            {
                return false;
            }
        }
    }
}
