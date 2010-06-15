using System;
using System.Web.UI;

namespace IdentityProviderDemo.Pages
{
    public partial class MetadataUploadPage : Page
    {/*
        protected void UploadButton_Click(object sender, EventArgs e)
        {
            if (_fileupload.HasFile)
            {
                XmlDocument doc;
                try
                {                    
                    doc = new XmlDocument();
                    doc.PreserveWhitespace = true;
                    doc.Load(new StreamReader(_fileupload.FileContent, Encoding.UTF8));
                } catch(Exception)
                {
                    _statusLabel.Text = "Unable to load metadata. File contents were not recognized as XML.";
                    return;
                }

                Saml20MetadataDocument metadata = new Saml20MetadataDocument(doc);
                IDPConfig.MetadataDocs.Add(metadata.EntityId, metadata);
                Response.Redirect("../Control.aspx", true);
            }
        }
        */

        protected void Page_Load(object sender, EventArgs e)        
        {
            
        }
    }
}
