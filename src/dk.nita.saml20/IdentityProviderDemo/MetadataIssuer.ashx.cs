using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.Bindings.SignatureProviders;
using dk.nita.saml20.config;
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
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;
            doc.LoadXml(Serialization.SerializeToXmlString(metadata));

            var signatureProvider = SignatureProviderFactory.CreateFromAlgorithmName(ShaHashingAlgorithm.SHA256);

            X509Certificate2 cert = IDPConfig.IDPCertificate;
            var id = doc.DocumentElement.GetAttribute("ID");
            signatureProvider.SignMetaData(doc, id, cert);

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

        public bool IsReusable
        {
            get
            {
                return false;
            }
        }
    }
}
