using System;
using System.Configuration;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Xml;
using dk.nita.saml20;
using IdentityProviderDemo.Logic;

namespace IdentityProviderDemo
{
    public partial class Control : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (VerifyDataFolder())
            {
                VerifyConfiguration();
                PopulateSPList();

                certLabel.Text = string.Format("Currently using certificate \"{0}\".", IDPConfig.IDPCertificate.SubjectName.Name);

                baseUrlLabel.Text = "Current server base url (EntityId): " + IDPConfig.ServerBaseUrl;

            }else
            {
                SetupPanel.Visible = true;
            }
        }

        private bool VerifyDataFolder()
        {
            string dataFolder = ConfigurationManager.AppSettings["IDPDataDirectory"];

            //Check for a valid value
            if(string.IsNullOrEmpty(dataFolder))
            {
                SetupPanel.Controls.Add(new LiteralControl("Missing \"IDPDataDirectory\" AppSetting value in web.config! Please provide a valid directory name for this value."));
                return false;
            }else
            {
                //Make sure the directory exists
                if(!Directory.Exists(dataFolder))
                {
                    SetupPanel.Controls.Add(new LiteralControl("The directory \"" + dataFolder + "\" specified as the \"IDPDataDirectory\" AppSetting value in web.config does not exist. Please create it and make sure it is writeable."));
                    return false;
                }else
                {
                    //Directory exists. Lets make sure it is writeable.

                    DirectoryInfo di = new DirectoryInfo(dataFolder);

                    DirectorySecurity ds = di.GetAccessControl();

                    AuthorizationRuleCollection arc = ds.GetAccessRules(true, true, typeof(NTAccount));

                    bool canModify = false;

                    foreach (FileSystemAccessRule fsar in arc)
                    {
                        if (fsar.IdentityReference.Value == WindowsIdentity.GetCurrent().Name)
                        {
                            if ((fsar.FileSystemRights & FileSystemRights.Modify) == FileSystemRights.Modify)
                            {
                                canModify = true;
                            }
                        }
                    }
                    
                    if (!canModify)
                    {
                        SetupPanel.Controls.Add(new LiteralControl("Windows identity running this website (" + WindowsIdentity.GetCurrent().Name + ") does not have \"Modify\" rights on the directory \"" + dataFolder + "\". Please navigate to the folder and choose \"properties\", go to the \"Security\" tab, and make sure that the user \"" + WindowsIdentity.GetCurrent().Name + "\" is in the list and has the \"modify\" permission checked."));
                    }

                    return canModify;
                }
            }
        }

        private void PopulateSPList()
        {
            ReadyPanel.Visible = true;
            ServiceProviderList.Controls.Clear();
          
            foreach (string entityID in IDPConfig.GetServiceProviderIdentifiers())
            {
                Panel p = new Panel();
                p.Style.Add(HtmlTextWriterStyle.MarginLeft, "10px");
                p.Style.Add(HtmlTextWriterStyle.MarginTop, "4px");
                p.Style.Add(HtmlTextWriterStyle.Color, "green");
                p.Controls.Add(new LiteralControl(" - " + entityID + " "));

                LinkButton removeBt = new LinkButton();
                removeBt.Text = "remove";
                removeBt.Command += removeBt_Command;
                removeBt.CommandName = entityID;
                p.Controls.Add(removeBt);

                ServiceProviderList.Controls.Add(p);
            }            
        }

        /// <summary>
        /// Removes an service provider from the list of recognized service providers.
        /// </summary>
        void removeBt_Command(object sender, CommandEventArgs e)
        {
            if (!string.IsNullOrEmpty(e.CommandName))
                IDPConfig.RemoveServiceProvider(e.CommandName);
        }

        /// <summary>
        /// Checks whether all required configuration elements are present. Redirects to the appropriate page if an element
        /// is missing.
        /// </summary>
        private void VerifyConfiguration()
        {
            if (IDPConfig.IDPCertificate == null)
                Response.Redirect("config/CertificateSelection.aspx", true);

            if (IDPConfig.ServerBaseUrl == null)
                Response.Redirect("config/BaseURL.aspx", true);            
        }


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
                }
                catch (Exception)
                {
                    _statusLabel.Text = "Unable to load metadata. File contents were not recognized as XML.";
                    return;
                }

                // Apparently updating the metadata. Remove old version.
                IDPConfig.AddServiceProvider(doc);
                PopulateSPList();
            }
        }

        protected void ClearCert_Click(object sender, EventArgs e)
        {
            IDPConfig.ClearCertificate();
            VerifyConfiguration(); 
        }

        protected void ChangeBaseUrl_Click(object sender, EventArgs e)
        {
            IDPConfig.ServerBaseUrl = null;
            VerifyConfiguration();
        }
    }
}
