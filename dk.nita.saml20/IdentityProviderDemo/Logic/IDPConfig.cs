using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Utils;

namespace IdentityProviderDemo.Logic
{
    /// <summary>
    /// Contains the settings for the identity provider.
    /// </summary>
    public class IDPConfig
    {        
        static IDPConfig()
        {
            _metadataDocs = new Dictionary<string, Saml20MetadataDocument>();
        }

        private static bool _configLoaded = false;
        private static bool _metadataLoaded = false;
        private const string _configFileName = "idpConfig.obj";
        private const string _spMetadataDir = "spmetadata";
        private static StoreName _storeName;
        private static StoreLocation _storeLocation;
        private static readonly Dictionary<string, Saml20MetadataDocument> _metadataDocs;

        private static X509Certificate2 _idpCertificate;
        /// <summary>
        /// The certificate of the identity provider.
        /// </summary>
        public static X509Certificate2 IDPCertificate
        {
            get 
            { 
                LoadConfig();
                return _idpCertificate;
            }
        }

        /// <summary>
        /// The service providers' metadata.
        /// </summary>
        private static Dictionary<string, Saml20MetadataDocument> MetadataDocs
        {
            get
            {
                LoadSPMetadata();
                return _metadataDocs;
            }
        }

        /// <summary>
        /// Adds the service provider with the given metadata to the list of known service providers.
        /// </summary>        
        public static void AddServiceProvider(XmlDocument doc)
        {
            Saml20MetadataDocument metadata = new Saml20MetadataDocument(doc);

            if (MetadataDocs.ContainsKey(metadata.EntityId))
                MetadataDocs.Remove(metadata.EntityId);

            MetadataDocs.Add(metadata.EntityId, metadata);

            SaveMetadata(metadata.EntityId, doc);
        }

        public static string SPMetadataDir
        {
            get
            {
                return Path.Combine(ConfigurationManager.AppSettings["IDPDataDirectory"], _spMetadataDir);
            }
        }

        private static void SaveMetadata(string entityId, XmlDocument entity)
        {
            string filename = GetFilename(entityId);
            string path = Path.Combine(SPMetadataDir, filename);

            FileStream fs = File.OpenWrite(path);

            string metadataString = entity.OuterXml;

            StreamWriter sw = new StreamWriter(fs);
            sw.Write(metadataString);

            sw.Close();
        }

        private static void DeleteSPMetadataFile(string entityID)
        {
            string filename = GetFilename(entityID);
            string path = Path.Combine(SPMetadataDir, filename);

            if(File.Exists(path))
                File.Delete(path);
        }

        private static void LoadSPMetadata()
        {
            if (!_metadataLoaded)
            {
                _metadataLoaded = true;

                if (!Directory.Exists(SPMetadataDir))
                    Directory.CreateDirectory(SPMetadataDir);

                foreach (string file in Directory.GetFiles(SPMetadataDir))
                {
                    string metadataString = File.ReadAllText(file);
                    try
                    {
                        XmlDocument doc = new XmlDocument();
                        doc.PreserveWhitespace = true;
                        doc.LoadXml(metadataString);

                        Saml20MetadataDocument metadata = new Saml20MetadataDocument(doc);

                        _metadataDocs.Add(metadata.EntityId, metadata);

                    }catch
                    {
                        //If for some reason there is a file in the directory which does not contain 
                        //valid data we just continue to the next file
                        continue;
                    }
                }
            }
        }

        /// <summary>
        /// Removes the metadata of the service provider with the given id.
        /// </summary>
        public static void RemoveServiceProvider(string entityID)
        {
            MetadataDocs.Remove(entityID);
            DeleteSPMetadataFile(entityID);
        }

        /// <summary>
        /// Retrieve metadata of the identity provider with the given id.
        /// </summary>
        /// <returns>null if the service provider is not recognized.</returns>
        public static Saml20MetadataDocument GetServiceProviderMetadata(string id)
        {
            if (MetadataDocs.ContainsKey(id))
                return MetadataDocs[id];

            return null;
        }

        /// <summary>
        /// Returns the number of known service providers.
        /// </summary>
        public static int ServiceProviderCount
        {
            get { return MetadataDocs.Count; }
        }

        /// <summary>
        /// Returns a list of known service providers.
        /// </summary>
        public static List<string> GetServiceProviderIdentifiers()
        {
            return new List<string>(MetadataDocs.Keys);
        }

        private static string _serverBaseUrl;

        /// <summary>
        /// The base URL from which endpoint addresses are created.
        /// </summary>
        public static string ServerBaseUrl
        {
            get
            {
                LoadConfig();
                return _serverBaseUrl;
            }
            set
            {
                _serverBaseUrl = value;
                SaveConfig();
            }
        }

        /// <summary>
        /// The name of the attributes that the identity provider offers to service providers.
        /// </summary>
        public readonly static string[] attributes = new string[]
            {   "urn:oid:2.5.4.3",                                          // (CommonName)
                "urn:oid:0.9.2342.19200300.100.1.3",                        // (email)
                "urn:oid:2.5.4.10",                                         // (OrganisationName)
                "urn:oid:1.3.6.1.4.1.1466.115.121.1.8",                     // (OCES Cert)
                "dk:gov:saml:attribute:CvrNumberIdentifier",                // (CVR number)
                "urn:dk:oes:2009-10:Xform:attribute:Role"                   // (Rolle)
            };

        private static string GetFilename(string entityID)
        {
            byte[] hash; 
            System.Security.Cryptography.MD5CryptoServiceProvider md5 = new System.Security.Cryptography.MD5CryptoServiceProvider(); 
            hash = md5.ComputeHash(Encoding.UTF8.GetBytes(entityID)); 
            
            // convert hash value to hex string 
            StringBuilder sb = new StringBuilder(); 
            foreach ( byte b in hash) 
            { 
                // convert each byte to a Hexadecimalstring 
                sb.Append(b.ToString("x2")); 
            } 

            return sb.ToString();
        }

        private static void LoadConfig()
        {
            if(!_configLoaded)
            {
                _configLoaded = true;
                string path = Path.Combine(ConfigurationManager.AppSettings["IDPDataDirectory"], _configFileName);
                if (!File.Exists(path))
                    return;

                FileStream fs = File.OpenRead(path);

                BinaryFormatter bf = new BinaryFormatter();

                FileConfig conf = (FileConfig) bf.Deserialize(fs);

                fs.Close();

                _serverBaseUrl = conf.BaseUrl;

                LoadCertificate(conf);
            }
        }

        private static void LoadCertificate(FileConfig conf)
        {
            if(!string.IsNullOrEmpty(conf.certThumbPrint))
            {
                _storeLocation = (StoreLocation) Enum.Parse(typeof (StoreLocation), conf.certLocation);
                _storeName = (StoreName)Enum.Parse(typeof(StoreName), conf.certStore);

                X509Store store = new X509Store(_storeName, _storeLocation);

                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection coll = store.Certificates.Find(X509FindType.FindByThumbprint, conf.certThumbPrint, true);
                if(coll.Count == 1)
                {
                    _idpCertificate = coll[0];
                }
            }
        }

        private static void SaveConfig()
        {
            string path = Path.Combine(ConfigurationManager.AppSettings["IDPDataDirectory"], _configFileName);

            FileConfig conf = new FileConfig();
            conf.BaseUrl = ServerBaseUrl;
            if(IDPCertificate != null)
            {
                conf.certThumbPrint = IDPCertificate.Thumbprint;
                conf.certLocation = _storeLocation.ToString();
                conf.certStore = _storeName.ToString();
            }
            FileStream fs = File.OpenWrite(path);

            BinaryFormatter bf = new BinaryFormatter();

            bf.Serialize(fs, conf);

            fs.Close();
        }

        public static void SetCertificate(X509Certificate2 certificate, StoreName name, StoreLocation location)
        {
            _idpCertificate = certificate;
            _storeName = name;
            _storeLocation = location;
            
            SaveConfig();
        }

        public static void ClearCertificate()
        {
            _idpCertificate = null;
            
            SaveConfig();
        }
    }

    [Serializable]
    public class FileConfig
    {
        public string BaseUrl;

        public string certThumbPrint;
        public string certLocation;
        public string certStore;

    }
}
