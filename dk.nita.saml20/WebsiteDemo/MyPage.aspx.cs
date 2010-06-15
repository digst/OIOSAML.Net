using System;
using System.Web.UI;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;

namespace WebsiteDemo
{
    public partial class WebForm1 : Page
    {
        protected  void Page_PreInit(object sender, EventArgs e)
        {
            
        }
        protected void Page_Load(object sender, EventArgs e)
        {            
            Title = "My page on SP " + SAML20FederationConfig.GetConfig().ServiceProvider.ID;
        }

        protected void Btn_Relogin_Click(object sender, EventArgs e)
        {
            Session[Saml20AbstractEndpointHandler.IDPForceAuthn] = true;

            Response.Redirect("/demo/login.ashx");
        }

        protected void Btn_ReloginNoForceAuthn_Click(object sender, EventArgs e)
        {
            Response.Redirect("/demo/login.ashx");
        }
        
    }
}
