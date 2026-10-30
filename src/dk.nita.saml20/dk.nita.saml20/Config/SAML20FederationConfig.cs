using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Xml;
using System.Xml.Serialization;
using dk.nita.saml20.Profiles.DKSaml20.Attributes;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Utils;
using Saml2.Properties;
using Trace = dk.nita.saml20.Utils.Trace;
using System.Security.Cryptography;

namespace dk.nita.saml20.config
{
    /// <summary>
    /// Configuration elements for SAML20 Federation
    /// To create a new XSD Run this command:
    /// xsd -t:dk.nita.saml20.config.SAML20Federation dk.nita.saml20.dll
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    [XmlRoot(ConfigurationConstants.SectionNames.SAML20Federation, Namespace = ConfigurationConstants.NamespaceUri, IsNullable = false)]
    public class SAML20FederationConfig : ConfigurationInstance<SAML20FederationConfig>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SAML20FederationConfig"/> class.
        /// </summary>
        public SAML20FederationConfig()
        {
            ServiceProvider = new ServiceProviderElement();
            _idpEndpoints = new IDPEndpoints();
        }

        /// <summary>
        /// Requested attributes
        /// </summary>
        [XmlElement]
        public RequestedAttributes RequestedAttributes;

        /// <summary>
        /// Service provider
        /// </summary>
        [XmlElement]
        public ServiceProviderElement ServiceProvider;

        private CommonDomainConfig _commonDomain;

        /// <summary>
        /// Gets or sets the common domain configuration section.
        /// </summary>
        [XmlElement(ElementName = "CommonDomain")]
        public CommonDomainConfig CommonDomain
        {
            get
            {
                if (_commonDomain == null)
                    _commonDomain = new CommonDomainConfig();
                return _commonDomain;
            }
            set
            {
                _commonDomain = value;
            }
        }

        private string _nameIdFormat;

        /// <summary>
        /// Gets or sets the NameIdFormat configuration
        /// </summary>
        [XmlElement(ElementName = "NameIdFormat")]
        public string NameIdFormat
        {
            get
            {
                if (_nameIdFormat == null)
                    return Saml20Constants.NameIdentifierFormats.Persistent;

                return _nameIdFormat;
            }
            set { _nameIdFormat = value; }
        }

        // default to false
        private Boolean _showError = false;

        /// <summary>
        /// Gets or sets the ShowError configuration
        /// NOTE: This setting should be FALSE for production, due to XML Encryption being vulnerable to attack
        ///       if information is leaked through error messages
        /// </summary>
        [XmlElement(ElementName = "ShowError")]
        public Boolean ShowError
        {
            get { return _showError; }
            set { _showError = value; }
        }

        private bool _allowAssuranceLevel = false;

        /// <summary>
        /// Allow OIOSAML2 assurance level validation.
        /// </summary>
        [XmlElement(ElementName = "AllowAssuranceLevel")]
        public bool AllowAssuranceLevel
        {
            get { return _allowAssuranceLevel; }
            set { _allowAssuranceLevel = value; }
        }

        // default to Substantial. Cooresponds to certificate level in the OIOSAML specification.
        private string _minimumAssuranceLevel = "3";

        /// <summary>
        /// Gets or sets the minimum assurance level configuration (spec 2.0)
        /// </summary>
        [XmlElement(ElementName = "MinimumAssuranceLevel")]
        public string MinimumAssuranceLevel
        {
            get { return _minimumAssuranceLevel; }
            set { _minimumAssuranceLevel = value; }
        }

        // default to Substantial. Cooresponds to certificate level in the OIOSAML specification.
        private string _minimumNsisLoa = "Substantial";

        /// <summary>
        /// Gets or sets the minimum NSIS level of assurance configuration (spec 3.0)
        /// </summary>
        [XmlElement(ElementName = "MinimumNsisLoa")]
        public string MinimumNsisLoa
        {
            get { return _minimumNsisLoa; }
            set
            {
                if (!DKSaml20NsisLoaAttribute.IsValidLevel(value))
                {
                    throw new ConfigurationErrorsException($"MinimumNsisLoa must be Low, Substantial or High, but was \"{value}\".");
                }
                _minimumNsisLoa = value;
            }
        }


        private IDPEndpoints _idpEndpoints;

        /// <summary>
        /// Gets or sets the IDP endpoints.
        /// </summary>
        /// <value>The IDP endpoints.</value>
        [XmlIgnore]
        public List<IDPEndPoint> IDPEndPoints
        {
            get { return _idpEndpoints.IDPEndPoints; }
            set { _idpEndpoints.IDPEndPoints = value; }
        }

        /// <summary>
        /// Gets or sets the endpoints.
        /// </summary>
        /// <value>The endpoints.</value>
        [XmlElement("IDPEndPoints")]
        public IDPEndpoints Endpoints
        {
            get { return _idpEndpoints; }
            set { _idpEndpoints = value; }
        }

        /// <summary>
        /// Metadata element
        /// </summary>
        [XmlElement("Metadata")] public ConfigMetadata Metadata;

        /// <summary>
        /// Finds an endpoint given its id.
        /// </summary>
        /// <param name="endPointId">The end point id.</param>
        /// <returns></returns>
        public IDPEndPoint FindEndPoint(string endPointId)
        {
            return IDPEndPoints.Find(delegate (IDPEndPoint ep) { return ep.Id == endPointId; });
        }
        /// <summary>
        /// AppSwitchReturnURL collection
        /// </summary>
        [XmlElement("AppSwitchReturnURL")]
        public List<AppSwitchReturnURL> AppSwitchReturnURL { get; set; }

        /// <summary>
        /// Finds Return URL for the specified <paramref name="appSwitchPlatform"/> in the SAML20Federation section.
        /// </summary>
        /// <param name="appSwitchPlatform">AppSwitch platform. Must be one of two values: 'Android' or 'iOS'.</param>
        /// <returns>String, containing the platform-specific Return URL.</returns>
        public string FindAppSwitchReturnUrlForPlatform(Platform appSwitchPlatform)
        {
           return AppSwitchReturnURL.SingleOrDefault(x => x.Platform == appSwitchPlatform)?.Value;
        }
        /// <summary>
        /// Initializes the config section by initializing the idp-endpoints
        /// </summary>
        protected override void Initialize()
        {
            _idpEndpoints.Initialize();
        }
    }

    /// <summary>
    /// Holds common domain configuration for a service provider
    /// </summary>
    public class CommonDomainConfig
    {
        /// <summary>
        /// Is common domain cookie reading enabled
        /// </summary>
        [XmlAttribute(AttributeName = "enabled")]
        public bool Enabled;

        /// <summary>
        /// A full url to the local common domain cookie reader endpoint.
        /// </summary>
        [XmlAttribute(AttributeName = "localReaderEndpoint")]
        public string LocalReaderEndpoint;
    }

    /// <summary>
    /// Configuration element that defines settings for generating metadata.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class ConfigMetadata
    {
        /// <summary>
        /// Artifact protocol binding is not a part of DK-SAML2.0 and should only be included in metadata
        /// when communicating with a non DK-SAML2.0 compliant IdP
        /// </summary>
        [XmlAttribute("IncludeArtifactEndpoints", Namespace = ConfigurationConstants.NamespaceUri)]
        public bool IncludeArtifactEndpoints;
    }

    /// <summary>
    /// Requested attributes configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class RequestedAttributes
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RequestedAttributes"/> class.
        /// </summary>
        public RequestedAttributes()
        {
            Attributes = new List<Attribute>();
        }

        /// <summary>
        /// Attributes
        /// </summary>
        [XmlElement("att")]
        public List<Attribute> Attributes;
    }

    /// <summary>
    /// Attribute configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class Attribute
    {
        /// <summary>
        /// Attribute name, eg. urn:oid:2.5.4.5 or urn:oid:2.5.4.3.
        /// </summary>
        [XmlAttribute("name", Namespace = ConfigurationConstants.NamespaceUri)]
        public string name;

        /// <summary>
        /// Is the attribute required
        /// </summary>
        [XmlAttribute("isRequired", Namespace = ConfigurationConstants.NamespaceUri)]
        public string required;

        /// <summary>
        /// Gets or sets a value indicating whether the attribute is required.
        /// </summary>
        /// <value>
        /// 	<c>true</c> if the attribute is required; otherwise, <c>false</c>.
        /// </value>
        [XmlIgnore]
        public bool IsRequired
        {
            get
            {
                if (string.IsNullOrEmpty(required))
                    return false;

                return Convert.ToBoolean(required);
            }

            set { required = Convert.ToString(value); }
        }
    }


    /// <summary>
    /// Endpoints configuration element.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class IDPEndpoints
    {
        [XmlIgnore]
        private string _metadataLocation;

        /// <summary>
        /// Watches the metadata location for changes
        /// </summary>
        private FileSystemWatcher _fileSystemWatcher;

        /// <summary>
        /// Initializes a new instance of the <see cref="IDPEndpoints"/> class.
        /// </summary>
        public IDPEndpoints()
        {
            IDPEndPoints = new List<IDPEndPoint>();
        }

        /// <summary>
        /// The directory in which the metadata files of trusted identity providers should be found.
        /// </summary>
        [XmlAttribute("metadata")]
        public string MetadataLocation
        {
            get { return _metadataLocation; }
            set
            {
                if (!Path.IsPathRooted(value))
                {
                    _metadataLocation = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, value);
                }
                else
                {
                    _metadataLocation = value;
                }
            }
        }

        /// <summary>
        /// The encodings that should be attempted when a metadata file does not contain an encoding attribute and 
        /// the signature doesn't validate. Contains a space-delimited list of encoding names to try out.
        /// </summary>
        [XmlAttribute("encodings")]
        public string encodings;

        /// <summary>
        /// URL to a page that is used, in case more than one IDPEndPoint is configured, 
        /// AND no Common Domain Cookie is set AND no default IDP is selected with the default-attribute.
        /// </summary>
        [XmlAttribute("idpSelectionUrl")]
        public string idpSelectionUrl;

        /// <summary>
        /// Contains Encoding instances of the the encodings that should by tried when a metadata file does not have its
        /// encoding specified.
        /// </summary>
        [XmlIgnore]
        private List<Encoding> _encodings;

        /// <summary>
        /// Finds an endpoint given its id.
        /// </summary>
        /// <param name="endPointId">The endpoint's id.</param>
        /// <returns></returns>
        public IDPEndPoint FindEndPoint(string endPointId)
        {
            return IDPEndPoints.Find(delegate (IDPEndPoint ep) { return ep.Id == endPointId; });
        }

        /// <summary>
        /// Returns a list of the encodings that should be tried when a metadata file does not contain a valid signature 
        /// or cannot be loaded by the XmlDocument class. Either returns a list specified by the administrator in the configuration file
        /// or a default list.
        /// </summary>
        private List<Encoding> _getEncodings()
        {
            if (_encodings != null)
                return _encodings;

            if (string.IsNullOrEmpty(encodings))
            {
                // If it has not been specified in the config file, use the defaults.
                _encodings = new List<Encoding>();
                _encodings.Add(Encoding.UTF8);
                _encodings.Add(Encoding.GetEncoding("iso-8859-1"));
                return _encodings;
            }

            string[] encs = encodings.Split(' ');
            _encodings = new List<Encoding>(encs.Length);
            foreach (string enc in encs)
                _encodings.Add(Encoding.GetEncoding(enc));

            return _encodings;
        }

        /// <summary>
        /// List of IdP endpoints
        /// </summary>
        [XmlElement("add")]
        public List<IDPEndPoint> IDPEndPoints;

        #region Handling of metadata files 

        /// <summary>
        /// The ids of the endpoints in the configuration file. A reload of the metadata never removes them.
        /// </summary>
        [XmlIgnore]
        private List<string> _configuredEndpointIds;

        /// <summary>
        /// The last metadata document that could be read from each file in the metadata location.
        /// </summary>
        [XmlIgnore]
        private Dictionary<string, XmlDocument> _metadataFiles = new Dictionary<string, XmlDocument>();

        /// <summary>
        /// When each file that kept its last version was first found unreadable.
        /// </summary>
        [XmlIgnore]
        private Dictionary<string, DateTime> _unreadableSince = new Dictionary<string, DateTime>();

        /// <summary>
        /// How long a file that can't be read keeps its last version. After that its keys are no longer trusted.
        /// </summary>
        [XmlIgnore]
        internal TimeSpan UnreadableGracePeriod = TimeSpan.FromMinutes(5);

        [XmlIgnore]
        private readonly object _reloadLock = new object();

        [XmlIgnore]
        private Timer _reloadTimer;

        /// <summary>
        /// Waits for a burst of file changes, such as copying a new file and deleting an old one, to finish before reloading.
        /// </summary>
        private static readonly TimeSpan ReloadDelay = TimeSpan.FromSeconds(2);

        private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Initializes the file system watcher to watch for changes in the metadata location
        /// </summary>
        private void InitializeFileSystemWatcher()
        {
            _reloadTimer = new Timer(_ => ReloadMetadata());
            _fileSystemWatcher = new FileSystemWatcher();
            _fileSystemWatcher.Filter = "*.*";
            _fileSystemWatcher.Changed += (sender, e) => ScheduleReload(ReloadDelay);
            _fileSystemWatcher.Created += (sender, e) => ScheduleReload(ReloadDelay);
            _fileSystemWatcher.Deleted += (sender, e) => ScheduleReload(ReloadDelay);
            _fileSystemWatcher.Renamed += (sender, e) => ScheduleReload(ReloadDelay);
            _fileSystemWatcher.Error += (sender, e) => RestartFileSystemWatcher();
            _fileSystemWatcher.Path = _metadataLocation;
            _fileSystemWatcher.EnableRaisingEvents = true;
        }

        /// <summary>
        /// The watcher stops raising events after an error, for example when a network share drops.
        /// </summary>
        private void RestartFileSystemWatcher()
        {
            try
            {
                _fileSystemWatcher.EnableRaisingEvents = false;
                _fileSystemWatcher.EnableRaisingEvents = true;
            }
            catch (Exception e)
            {
                Trace.TraceData(TraceEventType.Error, "Restarting the watcher of the IdP metadata location failed.", e.ToString());
            }
            ScheduleReload(ReloadDelay);
        }

        private void ScheduleReload(TimeSpan delay)
        {
            _reloadTimer.Change(delay, Timeout.InfiniteTimeSpan);
        }

        /// <summary>
        /// Reloads the metadata on a timer thread, where an exception would end the process.
        /// </summary>
        private void ReloadMetadata()
        {
            try
            {
                if (!LoadMetadata())
                    ScheduleReload(RetryDelay);
            }
            catch (Exception e)
            {
                Trace.TraceData(TraceEventType.Error, "Reloading the IdP metadata failed; retrying.", e.ToString());
                ScheduleReload(RetryDelay);
            }
        }

        /// <summary>
        /// Refreshes the information retrieved from the directory containing metadata files.
        /// </summary>
        internal void Initialize()
        {
            if (MetadataLocation == null)
                return;

            if (!Directory.Exists(MetadataLocation))
                throw new DirectoryNotFoundException(string.Format(Resources.MetadataLocationNotFound, MetadataLocation));

            // Watch first, so a change during the first load isn't missed.
            InitializeFileSystemWatcher();

            if (!LoadMetadata())
                ScheduleReload(RetryDelay);
        }

        /// <summary>
        /// Reads every metadata file in the metadata location and replaces the IdP endpoints in one step.
        /// <list type="bullet">
        /// <item>An endpoint from the configuration file is kept, with the metadata of its entity id, or none.</item>
        /// <item>An entity with metadata but no configured endpoint gets an endpoint, which goes again when its metadata files are gone.</item>
        /// <item>Several files with the same entity id are combined: the newest file gives the endpoints, and the keys of all of them are trusted.</item>
        /// <item>A file that can't be read now, for example while it is being written or is locked, keeps its last version
        /// for <see cref="UnreadableGracePeriod"/>; after that its keys are no longer trusted.</item>
        /// <item>A file that can be read but isn't usable metadata counts as removed.</item>
        /// </list>
        /// </summary>
        /// <returns>false if a file couldn't be read, so the reload should be retried.</returns>
        internal bool LoadMetadata()
        {
            lock (_reloadLock)
            {
                if (_configuredEndpointIds == null)
                    _configuredEndpointIds = IDPEndPoints.Select(endpoint => endpoint.Id).ToList();

                var complete = true;
                var now = DateTime.UtcNow;
                var metadataFiles = new Dictionary<string, XmlDocument>();
                var unreadableSince = new Dictionary<string, DateTime>();
                foreach (var file in Directory.GetFiles(MetadataLocation))
                {
                    var metadataFile = ReadMetadataFile(file, out var unreadable);
                    if (unreadable)
                    {
                        complete = false;
                        var since = _unreadableSince.TryGetValue(file, out var first) ? first : now;
                        unreadableSince[file] = since;
                        if (_metadataFiles.TryGetValue(file, out var previous))
                        {
                            if (now - since < UnreadableGracePeriod)
                            {
                                Trace.TraceData(TraceEventType.Warning, file, "Could not read the metadata file; using its last version until it can be read.");
                                metadataFile = previous;
                            }
                            else
                            {
                                Trace.TraceData(TraceEventType.Error, file, "Could not read the metadata file since " + since.ToString("o") + "; its last version is no longer used.");
                            }
                        }
                    }

                    if (metadataFile != null)
                        metadataFiles[file] = metadataFile;
                }
                _metadataFiles = metadataFiles;
                _unreadableSince = unreadableSince;

                var metadataByEntity = metadataFiles
                    .OrderByDescending(f => File.GetLastWriteTimeUtc(f.Key))
                    .Select(f => new Saml20MetadataDocument(f.Value))
                    .GroupBy(metadata => metadata.EntityId)
                    .ToDictionary(entity => entity.Key, entity => Combine(entity.ToList()));

                var endpoints = new List<IDPEndPoint>();
                foreach (var endpoint in IDPEndPoints)
                {
                    if (endpoint.Id != null && metadataByEntity.TryGetValue(endpoint.Id, out var metadata))
                    {
                        endpoint.metadata = metadata;
                        metadataByEntity.Remove(endpoint.Id);
                        endpoints.Add(endpoint);
                    }
                    else if (_configuredEndpointIds.Contains(endpoint.Id))
                    {
                        endpoint.metadata = null;
                        endpoints.Add(endpoint);
                    }
                }

                foreach (var metadata in metadataByEntity.Values)
                {
                    endpoints.Add(new IDPEndPoint { Id = metadata.EntityId, Name = metadata.EntityId, metadata = metadata });
                }

                IDPEndPoints = endpoints;
                return complete;
            }
        }

        /// <summary>
        /// Combines the metadata documents of one entity, newest first: the first gives the endpoints, and the keys of all are trusted.
        /// </summary>
        private static Saml20MetadataDocument Combine(List<Saml20MetadataDocument> documents)
        {
            var combined = documents[0];
            foreach (var other in documents.Skip(1))
                combined.Keys.AddRange(other.Keys);
            return combined;
        }

        /// <summary>
        /// Reads a SAML 2.0 metadata file with one EntityDescriptor.
        /// </summary>
        /// <param name="file">The file.</param>
        /// <param name="unreadable">true if the file couldn't be read or isn't well-formed XML, as while it is being written.</param>
        /// <returns>The metadata, or null if the file can't be read or isn't usable SAML 2.0 metadata.</returns>
        private XmlDocument ReadMetadataFile(string file, out bool unreadable)
        {
            unreadable = false;
            XmlDocument doc;
            try
            {
                doc = LoadFileAsXmlDocument(file);
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                Trace.TraceData(TraceEventType.Warning, file, "Could not read the metadata file.", e.ToString());
                unreadable = true;
                return null;
            }
            catch (Exception e)
            {
                Trace.TraceData(TraceEventType.Error, file, "The metadata file can't be used; ignored.", e.ToString());
                return null;
            }

            if (doc?.DocumentElement == null)
            {
                if (!LooksLikeXml(file))
                {
                    Trace.TraceData(TraceEventType.Information, file, "Not an XML file; ignored.");
                    return null;
                }

                Trace.TraceData(TraceEventType.Warning, file, "The metadata file is not well-formed XML.");
                unreadable = true;
                return null;
            }

            if (doc.DocumentElement.NamespaceURI != Saml20Constants.METADATA || doc.DocumentElement.LocalName != EntityDescriptor.ELEMENT_NAME)
            {
                Trace.TraceData(TraceEventType.Warning, file, "Not a SAML 2.0 metadata file with one EntityDescriptor; ignored.");
                return null;
            }

            try
            {
                new Saml20MetadataDocument(doc); // Fails here rather than during a reload if the document can't be used.
                return doc;
            }
            catch (Exception e)
            {
                Trace.TraceData(TraceEventType.Error, file, "The metadata file can't be used; ignored.", e.ToString());
                return null;
            }
        }

        /// <summary>
        /// Tells a file that isn't XML at all, such as a readme, from an XML file that is still being written.
        /// </summary>
        private static bool LooksLikeXml(string file)
        {
            try
            {
                using (var reader = new StreamReader(file, Encoding.UTF8, true))
                {
                    int c;
                    while ((c = reader.Read()) >= 0 && char.IsWhiteSpace((char)c))
                    {
                    }
                    return c == '<';
                }
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException)
            {
                return true;
            }
        }

        /// <summary>
        /// Loads a file into an XmlDocument. If the loading or the signature check fails, the method will retry using another encoding.
        /// </summary>        
        private XmlDocument LoadFileAsXmlDocument(string filename)
        {
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;

            try
            {
                // First attempt a standard load, where the XML document is expected to declare its encoding by itself.
                doc.Load(filename);
                try
                {
                    if (XmlSignatureUtils.IsSigned(doc) && !XmlSignatureUtils.CheckSignature(doc))
                        throw new InvalidOperationException("Invalid file signature");
                    // Throw an exception to get into quirksmode.
                }
                catch (CryptographicException)
                {
                    //Ignore cryptographic exception caused by Geneva server's inability to generate a
                    //.net compliant xml signature
                    return ParseGenevaServerMetadata(doc);
                }
                return doc;
            }
            catch (XmlException)
            {
                // Enter quirksmode
                List<Encoding> encs = _getEncodings();
                foreach (Encoding encoding in encs)
                {
                    StreamReader reader = null;
                    try
                    {
                        reader = new StreamReader(filename, encoding);
                        doc.Load(reader);
                        if (XmlSignatureUtils.IsSigned(doc) && !XmlSignatureUtils.CheckSignature(doc))
                            continue;
                    }
                    catch (XmlException)
                    { continue; }
                    finally
                    {
                        if (reader != null)
                            reader.Close();
                    }

                    return doc;
                }
            }
            return null;
        }

        private static XmlDocument ParseGenevaServerMetadata(XmlDocument doc)
        {
            if (doc == null) throw new ArgumentNullException("doc");
            if (doc.DocumentElement == null) throw new ArgumentException("DocumentElement cannot be null", "doc");
            XmlDocument other = new XmlDocument();
            other.XmlResolver = null;
            other.PreserveWhitespace = true;

            other.LoadXml(doc.OuterXml);

            List<XmlNode> remove = new List<XmlNode>();

            foreach (XmlNode node in other.DocumentElement.ChildNodes)
            {
                if (node.Name != IDPSSODescriptor.ELEMENT_NAME)
                {
                    remove.Add(node);
                }
            }

            foreach (XmlNode node in remove)
            {
                other.DocumentElement.RemoveChild(node);
            }

            return other;
        }

        #endregion
    }

    /// <summary>
    /// Service provider configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class ServiceProviderElement
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ServiceProviderElement"/> class.
        /// </summary>
        public ServiceProviderElement()
        {
            ContactPerson = new List<Contact>();
        }

        private string _id;

        /// <summary>
        /// Gets or sets the ID.
        /// </summary>
        /// <value>The ID.</value>
        [XmlAttribute(AttributeName = "id")]
        public string ID
        {
            get
            {
#if DEBUG
                if (_id == "urn:")
                {
                    string machineName = Environment.MachineName.ToLower();
                    return "urn:" + machineName.Substring(0, 1).ToUpper() + machineName.Remove(0, 1);
                }
#endif

                return _id;
            }
            set
            {
                if (!Uri.IsWellFormedUriString(value, UriKind.RelativeOrAbsolute))
                    throw new ConfigurationErrorsException(string.Format(Resources.InvalidWellformedAbsoluteUriString, value));

                _id = value;
            }
        }


        private string _server;

        /// <summary>
        /// Gets or sets the server.
        /// </summary>
        /// <value>The server.</value>
        [XmlAttribute(AttributeName = "server")]
        public string Server
        {
            get
            {
#if DEBUG
                if (_server == "http://" || _server == "https://")
                    return _server + Environment.MachineName.ToLower() + "." + Environment.GetEnvironmentVariable("USERDNSDOMAIN").ToLower();
#endif
                return _server;
            }
            set { _server = value; }
        }

        /// <summary>
        /// List of service endpoints
        /// </summary>
        [XmlElement("ServiceEndpoint")] public List<Saml20ServiceEndpoint> serviceEndpoints;

        /// <summary>
        /// Gets the logout endpoint.
        /// </summary>
        /// <value>The logout endpoint.</value>
        public Saml20ServiceEndpoint LogoutEndpoint
        {
            get
            {
                return FindEndpoint(EndpointType.LOGOUT);
            }
        }

        /// <summary>
        /// Gets the sign on endpoint.
        /// </summary>
        /// <value>The sign on endpoint.</value>
        public Saml20ServiceEndpoint SignOnEndpoint
        {
            get
            {
                return FindEndpoint(EndpointType.SIGNON);
            }
        }

        /// <summary>
        /// Gets the metadata endpoint.
        /// </summary>
        /// <value>The metadata endpoint.</value>
        public Saml20ServiceEndpoint MetadataEndpoint
        {
            get
            {
                return FindEndpoint(EndpointType.METADATA);
            }
        }

        private Saml20ServiceEndpoint FindEndpoint(EndpointType type)
        {
            return serviceEndpoints.Find(delegate (Saml20ServiceEndpoint ep) { return ep.endpointType == type; });
        }

        /// <summary>
        /// Organization
        /// </summary>
        [XmlElement(Namespace = Saml20Constants.METADATA)]
        public Organization Organization;

        /// <summary>
        /// Contact person
        /// </summary>
        [XmlElement(Namespace = Saml20Constants.METADATA)]
        public List<Contact> ContactPerson;
    }

    /// <summary>
    /// Holds NameIdFormats supported by the service provider
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class NameIdFormatsElement
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NameIdFormatsElement"/> class.
        /// </summary>
        public NameIdFormatsElement()
        {
            NameIdFormats = new List<NameIdFormatElement>();
        }

        /// <summary>
        /// Shorthand for supporting all NameIdFormats
        /// </summary>
        [XmlAttribute(AttributeName = "all")]
        public bool All;

        /// <summary>
        /// List of supported NameFormatIds
        /// </summary>
        [XmlElement(ElementName = "add")]
        public List<NameIdFormatElement> NameIdFormats;
    }

    /// <summary>
    /// An element that holds a single supported NameIdFormat
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class NameIdFormatElement
    {
        /// <summary>
        /// The NameIdFormat
        /// </summary>
        [XmlAttribute(AttributeName = "nameIdFormat")]
        public string NameIdFormat;
    }

    /// <summary>
    /// The service provider behaviour configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public enum ServiceProviderBehaviour
    {
        /// <summary>
        /// Keep token
        /// </summary>
        KeepToken,
        /// <summary>
        /// Translate token
        /// </summary>
        TranslateToken
    }

    /// <summary>
    /// The Saml20Service endpoint configuration element
    /// </summary>
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class Saml20ServiceEndpoint
    {
        /// <summary>
        /// The local path to the url on which this endpoint should be placed.
        /// </summary>
        [XmlAttribute("localpath")]
        public string localPath;

        /// <summary>
        /// Type of endpoint
        /// </summary>
        [XmlAttribute("type")]
        public EndpointType endpointType;

        /// <summary>
        /// Numeric index of this endpoint
        /// </summary>
        [XmlAttribute("index")]
        public ushort endPointIndex;

        /// <summary>
        /// Redirect to this url on succesful request
        /// </summary>
        [XmlAttribute("redirectUrl")]
        public string RedirectUrl;

        /// <summary>
        /// Saml binding
        /// </summary>
        [XmlAttribute("binding")]
        public SAMLBinding Binding = SAMLBinding.NOT_SET;

        /// <summary>
        /// Error handling behaviour
        /// </summary>
        [XmlAttribute("errorBehaviour")]
        public ErrorBehaviour ErrorBehaviour = ErrorBehaviour.SHOWPAGE;
    }

    /// <summary>
    /// Endpoint types (signon, logout or metadata)
    /// </summary>
    public enum EndpointType
    {
        /// <summary>
        /// Signon endpoint
        /// </summary>
        [XmlEnum("signon")]
        SIGNON,
        /// <summary>
        /// Logout endpoint
        /// </summary>
        [XmlEnum("logout")]
        LOGOUT,
        /// <summary>
        /// Logout endpoint
        /// </summary>
        [XmlEnum("soaplogout")]
        SOAPLOGOUT,
        /// <summary>
        /// Metadata endpoint
        /// </summary>
        [XmlEnum("metadata")]
        METADATA
    }

    /// <summary>
    /// Error handling behaviour (showpage, throwexception)
    /// </summary>
    public enum ErrorBehaviour
    {
        /// <summary>
        /// ShowPage behaviour
        /// </summary>
        [XmlEnum("showpage")]
        SHOWPAGE,
        /// <summary>
        /// ThrowException behaviour
        /// </summary>
        [XmlEnum("throwexception")]
        THROWEXCEPTION
    }

    /// <summary>
    /// the IDPEndpoint configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class IDPEndPoint
    {
        /// <summary>
        /// The metadata associated with the endpoint.
        /// </summary>
        [XmlIgnore]
        public Saml20MetadataDocument metadata;

        /// <summary>
        /// Id
        /// </summary>
        [XmlAttribute(AttributeName = "id")]
        public string Id;

        /// <summary>
        /// Name
        /// </summary>
        [XmlAttribute(AttributeName = "name")]
        public string Name;

        /// <summary>
        /// Override option for the default UTF-8 encoding convention on SAML responses
        /// </summary>
        [XmlAttribute(AttributeName = "responseEncoding")]
        public string ResponseEncoding;

        /// <summary>
        /// Enable quirks mode
        /// </summary>
        [XmlAttribute(AttributeName = "QuirksMode")]
        public bool QuirksMode;

        /// <summary>
        /// Omit signature checks on assertions.
        /// </summary>
        [XmlAttribute(AttributeName = "omitAssertionSignatureCheck")]
        public bool OmitAssertionSignatureCheck;

        /// <summary>
        /// Force authentication on each authnrequest
        /// </summary>
        [XmlAttribute(AttributeName = "forceAuthn")]
        public bool ForceAuthn;

        /// <summary>
        /// AuthnRequest is passive
        /// </summary>
        [XmlAttribute(AttributeName = "isPassive")]
        public bool IsPassive;

        /// <summary>
        /// Use default in case common domain cookie is not set, and more than one endpoint is available 
        /// </summary>
        [XmlAttribute(AttributeName = "default")]
        public bool Default;

        /// <summary>
        /// When using RSA keys SHA256 is the default for signing SAML requests. This allows for backwards compatibility if the Identity Provider only support RSA SHA1
        /// </summary>
        [XmlAttribute(AttributeName = "ShaHashingAlgorithm")]
        public string ShaHashingAlgorithm
        {
            get { return _shaHashingAlgorithm; }
            set { _shaHashingAlgorithm = value; }
        }

        /// <summary>
        /// Certificate validation
        /// </summary>
        [XmlElement(ElementName = "CertificateValidation")]
        public CertificateValidationElements CertificateValidation;

        /// <summary>
        /// AttributeQuery configuration parameters
        /// </summary>
        [XmlElement(ElementName = "AttributeQuery")]
        public HttpBasicAuthElement AttributeQuery;

        /// <summary>
        /// ArtifactResolution configuration parameters
        /// </summary>
        [XmlElement(ElementName = "ArtifactResolution")]
        public HttpBasicAuthElement ArtifactResolution;

        /// <summary>
        /// Single sign on
        /// </summary>
        [XmlElement(ElementName = "SSO")]
        public IDPEndPointElement SSOEndpoint;

        /// <summary>
        /// Single log off
        /// </summary>
        [XmlElement(ElementName = "SLO")]
        public IDPEndPointElement SLOEndpoint;

        /// <summary>
        /// Common Domain Cookie settings
        /// </summary>
        [XmlElement(ElementName = "CDC")]
        public CDCElement CDC;

        // Default value is SHA256
        private string _shaHashingAlgorithm = config.ShaHashingAlgorithm.SHA256.ToString();

        /// <summary>
        /// Get a URL that redirects the user to the login-page for this IDPEndPoint
        /// </summary>
        /// <returns></returns>
        public string GetIDPLoginUrl(bool forceAuthn, bool isPassive, string desiredNsisLoa, string desiredProfile, string appSwitchPlatform = null)
        {
            return IDPSelectionUtil.GetIDPLoginUrl(Id, forceAuthn, isPassive, desiredNsisLoa, desiredProfile, appSwitchPlatform);
        }
    }

    /// <summary>
    /// Holds rules for certificate validation
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class CertificateValidationElements
    {
        private List<CertificateValidationElement> _elems;

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateValidationElements"/> class.
        /// </summary>
        public CertificateValidationElements()
        {
            _elems = new List<CertificateValidationElement>();
        }

        /// <summary>
        /// List certificate validation implementations
        /// </summary>
        [XmlElement(ElementName = "add")]
        public List<CertificateValidationElement> CertificateValidations;

    }

    /// <summary>
    /// A single certificate validation element
    /// </summary>
    public class CertificateValidationElement
    {
        /// <summary>
        /// The concrete type that implements the ICertificateValidationSpecification interface.
        /// </summary>
        [XmlAttribute(AttributeName = "type")]
        public string type;
    }

    /// <summary>
    /// Holds Http Basic Auth settings
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class HttpBasicAuthElement
    {
        /// <summary>
        /// Is http basic auth enabled
        /// </summary>
        [XmlAttribute(AttributeName = "enableHttpBasicAuth")]
        public bool Enabled;

        /// <summary>
        /// The username
        /// </summary>
        [XmlAttribute(AttributeName = "username")]
        public string Username;

        /// <summary>
        /// The password
        /// </summary>
        [XmlAttribute(AttributeName = "password")]
        public string Password;
    }

    /// <summary>
    /// Holds Common Domain Cookie settings
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class CDCElement
    {
        /// <summary>
        /// Extra common domain cookie settings.
        /// </summary>
        [XmlElement(ElementName = "Settings")]
        public ExtraSettings ExtraSettings;

    }

    /// <summary>
    /// Extra key value settings for a configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class ExtraSettings
    {
        /// <summary>
        /// List of extra settings
        /// </summary>
        [XmlElement(ElementName = "add")]
        public List<KeyValue> KeyValues;
    }

    /// <summary>
    /// Hold key value pairs.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class KeyValue
    {
        /// <summary>
        /// The key (name)
        /// </summary>
        [XmlAttribute(AttributeName = "key")]
        public string Key;

        /// <summary>
        /// The value
        /// </summary>
        [XmlAttribute(AttributeName = "value")]
        public string Value;

    }

    /// <summary>
    /// The IDPEndPointElement configuration element
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    public class IDPEndPointElement
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IDPEndPointElement"/> class.
        /// </summary>
        public IDPEndPointElement()
        { }

        /// <summary>
        /// Constructor that converts the Saml20 Endpoint element to our IDPEndpointElement.
        /// </summary>        
        public IDPEndPointElement(Endpoint endpoint)
        {
            if (endpoint == null)
                throw new ArgumentNullException("endpoint");

            Url = endpoint.Location;
            switch (endpoint.Binding)
            {
                case Saml20Constants.ProtocolBindings.HTTP_Post:
                    Binding = SAMLBinding.POST;
                    break;
                case Saml20Constants.ProtocolBindings.HTTP_Redirect:
                    Binding = SAMLBinding.REDIRECT;
                    break;
                case Saml20Constants.ProtocolBindings.HTTP_Artifact:
                    Binding = SAMLBinding.ARTIFACT;
                    break;
                case Saml20Constants.ProtocolBindings.HTTP_SOAP:
                    Binding = SAMLBinding.SOAP;
                    break;
                default:
                    throw new InvalidOperationException("Binding not supported: " + endpoint.Binding);
            }
        }

        /// <summary>
        /// Url
        /// </summary>
        [XmlAttribute(AttributeName = "url")]
        public string Url;

        /// <summary>
        /// Binding
        /// </summary>
        [XmlAttribute(AttributeName = "binding")]
        public SAMLBinding Binding;

        /// <summary>
        /// Force a different protocol binding
        /// </summary>
        [XmlAttribute(AttributeName = "ForceProtocolBinding")]
        public string ForceProtocolBinding;

        /// <summary>
        /// Allows the caller to access the xml representation of an assertion before it's 
        /// translated to a strongly typed instance
        /// </summary>
        [XmlAttribute(AttributeName = "idpTokenAccessor")]
        public string IdpTokenAccessor;
    }

    /// <summary>
    /// Saml binding types
    /// </summary>
    [Serializable]
    [XmlType(Namespace = ConfigurationConstants.NamespaceUri)]
    [Flags]
    public enum SAMLBinding
    {
        /// <summary>
        /// No binding set.
        /// </summary>
        NOT_SET = 0,
        /// <summary>
        /// POST binding
        /// </summary>
        POST = 1,
        /// <summary>
        /// Redirect binding
        /// </summary>
        REDIRECT = 2,
        /// <summary>
        /// Artifact binding
        /// </summary>
        ARTIFACT = 4,
        /// <summary>
        /// SOAP binding
        /// </summary>
        SOAP = 8,
    }
}