using dk.nita.saml2.ext.brs.schema;

namespace dk.nita.saml2.ext.brs.schema
{
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "2.0.50727.1432")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = BRSConstants.XML_NAMESPACE)]
    [System.Xml.Serialization.XmlRootAttribute("MissingAuthorisationRequest", Namespace = BRSConstants.XML_NAMESPACE, IsNullable = false)]
    public class MissingAuthorisationRequestType {
    
        private string sessionIndexField;
    
        private AuthorisationType authorisationField;
    
        private string targetUrlField;
    
        /// <remarks/>
        public string SessionIndex {
            get {
                return this.sessionIndexField;
            }
            set {
                this.sessionIndexField = value;
            }
        }
    
        /// <remarks/>
        public AuthorisationType Authorisation {
            get {
                return this.authorisationField;
            }
            set {
                this.authorisationField = value;
            }
        }
    
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType="anyURI")]
        public string TargetUrl {
            get {
                return this.targetUrlField;
            }
            set {
                this.targetUrlField = value;
            }
        }
    }
}