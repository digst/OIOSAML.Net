using System;
using System.Collections.Generic;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using dk.nita.saml20.config;

namespace WebsiteDemo
{
    public partial class IDPSelectionDemo : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            litIDPList.Text = "<ul>";
            SAML20FederationConfig.GetConfig().Endpoints.IDPEndPoints.ForEach(idp =>
                litIDPList.Text += "<li><a href=\"" + idp.GetIDPLoginUrl() + "\">" + (string.IsNullOrEmpty(idp.Name) ? idp.Id : idp.Name) + "</a></li>");
            litIDPList.Text += "</ul>";
        }
    }
}
