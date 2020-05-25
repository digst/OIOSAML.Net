using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;
using dk.nita.saml20.Session;

namespace dk.nita.saml20.config
{
    /// <summary>
    /// Common federation parameters container - used by federation initiators to populate the intended audiences in a saml assertion
    /// and by federation receivers to validate the incoming saml assertions intended audiences against the list of configured 
    /// allowed audiences
    /// </summary>
    [Serializable]
    [XmlType(AnonymousType = true, Namespace = ConfigurationConstants.NamespaceUri)]
    [XmlRoot(ConfigurationConstants.SectionNames.Federation, Namespace = ConfigurationConstants.NamespaceUri, IsNullable = false)]
    public class FederationConfig : ConfigurationInstance<FederationConfig>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FederationConfig"/> class.
        /// </summary>
        public FederationConfig()
        {

        }

        /// <summary>
        /// The list of signing certificates - each represented by an X509 certificate reference
        /// To create a new XSD Run this command:
        /// xsd -t:Safewhere.Config.Federation   Safewhere.dll
        /// Certificate used to sign exchanged saml tokens
        /// </summary>
        [XmlArray("SigningCertificates", IsNullable = false)]
        [XmlArrayItem("SigningCertificate", IsNullable = false)]
        public List<Certificate> SigningCertificates;

        // default to 30 minutes
        private int _sessionTimeout = 30;

        // As default the component does not allow open redirect attacks.
        private bool _preventOpenRedirectAttack = true;

        // Default value is SHA256
        private string _metaDataShaHashingAlgorithm = ShaHashingAlgorithm.SHA256.ToString();

        /// <summary>
        /// SHA256 is the default for signing meta data. This allows for backwards compatibility if the Identity Provider only supports RSA SHA1
        /// </summary>
        [XmlElement(ElementName = "MetaDataShaHashingAlgorithm")]
        public string MetaDataShaHashingAlgorithm
        {
            get { return _metaDataShaHashingAlgorithm; }
            set { _metaDataShaHashingAlgorithm = value; }
        }

        /// <summary>
        /// Gets or sets the SessionTimeout configuration
        /// </summary>
        [XmlElement(ElementName = "SessionTimeout")]
        public int SessionTimeout
        {
            get { return _sessionTimeout; }
            set { _sessionTimeout = value; }
        }

        private string _sessionCookieName = "oiosamlSession";

        /// <summary>
        /// Name used for the session cookie
        /// </summary>
        [XmlElement(ElementName = "SessionCookieName")]
        public string SessionCookieName
        {
            get => _sessionCookieName;
            set => _sessionCookieName = value;
        }

        /// <summary>
        /// Specifies whether or not to prevent open redirect attacks by checking if return URL is local.
        /// Default value is true.
        /// </summary>
        [XmlElement(ElementName = "PreventOpenRedirectAttack")]
        public bool PreventOpenRedirectAttack
        {
            get { return _preventOpenRedirectAttack; }
            set { _preventOpenRedirectAttack = value; }
        }

        /// <summary>
        /// The list of audience uris that are allowed by a receiver
        /// </summary>
        public AudienceUris AllowedAudienceUris;

        /// <summary>
        /// The list of intended audience uris
        /// </summary>
        public AudienceUris IntendedAudienceUris;

        /// <summary>
        /// The list of trusted issuers - each represented by an X509 certificate reference
        /// </summary>
        [XmlArrayItem("TrustedIssuers", IsNullable = false)]
        public Certificate[] TrustedIssuers;

        /// <summary>
        /// The type of the audit logging provider. Provide the fully qualified name of the type implementing the IAuditLogger interface.
        /// </summary>
        [XmlAttribute("auditLoggingType")]
        public string AuditLoggingType;

        /// <summary>
        /// The type of the session provider. Provide the fully qualified name of the type implementing the <see cref="ISessionStoreProvider"/> interface.
        /// </summary>
        [XmlAttribute("sessionType")]
        public string SessionType;

        private ActionsConfig _actions;

        /// <summary>
        /// Gets the actions.
        /// </summary>
        /// <value>The actions.</value>
        [XmlElement]
        public ActionsConfig Actions
        {
            get
            {
                if (_actions == null)
                {
                    _actions = new ActionsConfig();
                }
                return _actions;
            }
            set { _actions = value; }
        }

        /// <summary>
        /// Determines the first valid certificate from the configuration
        /// </summary>
        /// <returns></returns>
        public X509Certificate2 GetFirstValidCertificate()
        {
            foreach (var certificate in SigningCertificates)
            {
                var x509Certificate = certificate.GetFirstValidX509Certificate();
                if (x509Certificate == null)
                    continue;

                return x509Certificate;
            }

            var msg = $"Found no valid certificate configured in the certificate configuration. Make sure at least one valid certificate is configured.";
            throw new ConfigurationErrorsException(msg);
        }

        private int _allowedClockSkewMinutes = 5;

        /// <summary>
        /// Clock skew in minutes to validate NotBefore, NotOnOrAfter, and validUntil 
        /// </summary>
        [XmlElement(ElementName = "AllowedClockSkewMinutes")]
        public int AllowedClockSkewMinutes
        {
            get { return _allowedClockSkewMinutes; }
            set => _allowedClockSkewMinutes = value;
        }
    }


    /// <summary>
        /// The Actions configuration element class
        /// </summary>
        [Serializable]
    public class ActionsConfig
    {
        private ActionConfigAbstract[] _actionList;

        /// <summary>
        /// Gets the list of config actions.
        /// </summary>
        /// <value>The list of actions</value>
        [XmlElement("add", typeof(ActionConfigAdd))]
        [XmlElement("remove", typeof(ActionConfigRemove))]
        [XmlElement("clear", typeof(ActionConfigClear))]
        public ActionConfigAbstract[] ActionList
        {
            get { return _actionList ?? new ActionConfigAbstract[] { }; }
            set { _actionList = value; }
        }
    }

    /// <summary>
    /// Base class for config actions
    /// </summary>
    [Serializable]
    public class ActionConfigAbstract
    {
        private string _name;

        /// <summary>
        /// Gets or sets the name.
        /// </summary>
        /// <value>The name.</value>
        [XmlAttribute("name")]
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }
    }

    /// <summary>
    /// Represents an &lt;add&gt; tag
    /// </summary>
    [Serializable]
    public class ActionConfigAdd : ActionConfigAbstract
    {
        private string _type;

        /// <summary>
        /// Gets or sets the type of a class that implements the IAction interface.
        /// </summary>
        /// <value>The type.</value>
        [XmlAttribute("type")]
        public string Type
        {
            get { return _type; }
            set { _type = value; }
        }
    }

    /// <summary>
    /// Represents a &lt;clear&gt; tag
    /// </summary>
    [Serializable]
    public class ActionConfigClear : ActionConfigAbstract
    {

    }

    /// <summary>
    /// Represents a &lt;remove&gt; tag
    /// </summary>
    [Serializable]
    public class ActionConfigRemove : ActionConfigAbstract
    {

    }

}
