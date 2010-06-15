using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Web.UI;
using System.Web.UI.WebControls;
using IdentityProviderDemo.Logic;

namespace IdentityProviderDemo
{
    public partial class CertificateSelection : Page
    {

        protected override void OnInit(EventArgs e)
        {            
            PopulateDropdownWithEnum(StoreLocationDropDown, typeof(StoreLocation));
            PopulateDropdownWithEnum(CertificateStoreDropDown, typeof(StoreName));            
        }


        protected void Page_Load(object sender, EventArgs e)
        {
            if (IsPostBack)
                RenderCertifateSelection();
            
        }

        private static void PopulateDropdownWithEnum(ListControl list, Type enumType)
        {
            foreach (StoreName element in Enum.GetValues(enumType))
            {
                string s = Regex.Replace(Enum.GetName(enumType, element), "([A-Z])", " $1").Trim();
                string value = Convert.ToString((int)element);
                list.Items.Add(new ListItem(s, value));
            }            
        }

        /// <summary>
        /// Returns the selected item from a drop down list as the corresponding enum instance.
        /// </summary>
        private static T GetSelectedEnum<T>( ListControl list )
        {
            return (T) Enum.ToObject(typeof (T), Convert.ToInt32(list.SelectedValue));
        }

        private void RenderCertifateSelection()
        {
            WriteMessage(string.Empty);

            X509Certificate2Collection certificates = GetCertificates();
            if (certificates == null) // error occurred.
                return;

            if (certificates.Count == 0)
            {
                WriteMessage("The selected certificate store is empty.");
            }
            else
            {
                WriteMessage("Select the certificate that will be used by the identity provider.");
                foreach (X509Certificate2 cert in certificates)
                {
                    LinkButton button = new LinkButton();
                    button.Text = cert.SubjectName.Name;
                    button.CommandName = cert.Thumbprint;
                    button.Command += button_Command;                    

                    if (!cert.HasPrivateKey)
                    {
                        button.Style.Add(HtmlTextWriterStyle.TextDecoration, "line-through");
                        button.Attributes.Add("title", "Private key of certificate is not accessible.");
                        button.Enabled = false;
                    }

                    CertificatePanel.Controls.Add(button);                    
                    CertificatePanel.Controls.Add(new LiteralControl("<div>" + cert.Thumbprint + "</div><br/>"));
                }
            }

        }

        /// <summary>
        /// Retrieves the list of certificates from the certificate store that is currently selected by the user.
        /// </summary>
        private X509Certificate2Collection GetCertificates()
        {
            StoreName storeName = GetSelectedEnum<StoreName>(CertificateStoreDropDown);
            StoreLocation storeLocation = GetSelectedEnum<StoreLocation>(StoreLocationDropDown);
            X509Store store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);                
                return store.Certificates;
            }
            catch (CryptographicException ex)
            {
                WriteWarning(ex.Message);
                return null;
            }
            finally
            {
                store.Close();
            }            
        }


        void button_Command(object sender, CommandEventArgs e)
        {
            X509Certificate2Collection certs = GetCertificates();
            
            // find the right one.
            X509Certificate2 IDPCertificate = null;
            foreach (X509Certificate2 cert in certs)
            {
                if (cert.Thumbprint == e.CommandName)
                {
                    IDPCertificate = cert;
                    break;
                }
            }

            if (IDPCertificate == null)
            {
                WriteWarning("An unknown error occurred when retrieving the certificate.");
                return;
            }
             
            if (!hasAccessToPrivateKey(IDPCertificate))
                return;

            IDPConfig.SetCertificate(IDPCertificate, GetSelectedEnum<StoreName>(CertificateStoreDropDown), GetSelectedEnum<StoreLocation>(StoreLocationDropDown));

            Response.Redirect("../Control.aspx");                               
        }

        /// <summary>
        /// Checks if the private key of the certificate can be read. If it is inaccessible, an error message is displayed to the user.
        /// </summary>
        private bool hasAccessToPrivateKey(X509Certificate2 cert)
        {
            // It is not possible to select a certificate without private key in the UI, but just to be on the safe side.
            if (!cert.HasPrivateKey)
            {
                WriteWarning("The selected certificate does not contain a private key.");
                return false;
            }

            try
            {
                AsymmetricAlgorithm key = cert.PrivateKey;
                return true;
            }
            catch (CryptographicException)
            {
                WriteWarning("The private key of the certificate can not be accessed. Make sure that the IIS user has read access to the certificate.");
                return false;
            }
        }

        private void WriteMessage(string  message)
        {
            messageLabel.Text = message;
            messageLabel.Style.Add(HtmlTextWriterStyle.Color, "black");
        }

        private void WriteWarning(string warning)
        {
            messageLabel.Text = warning;
            messageLabel.Style.Add(HtmlTextWriterStyle.Color, "red");
        }

    }
}
