using System;
using System.Web.UI;
using IdentityProviderDemo.Logic;

namespace IdentityProviderDemo
{
    public partial class BaseURL : Page
    {
        protected override void OnInit(EventArgs e)
        {
            UriBuilder suggestedURL = new UriBuilder(Request.Url);
            int index = suggestedURL.Path.LastIndexOf("/config");
            if (index != -1)
                suggestedURL.Path = suggestedURL.Path.Substring(0, index + 1);

            baseurl.Text = suggestedURL.ToString();
        }

        protected void Page_Load(object sender, EventArgs e)
        {
            if (IsPostBack)            
                HandleUserInput();           
        }

        private void HandleUserInput()
        {
            string url = baseurl.Text;
            if (Uri.IsWellFormedUriString(url, UriKind.Absolute))
            {
                IDPConfig.ServerBaseUrl = url;
                Response.Redirect("../Control.aspx");
            } else
            {
                MessageLabel.Text = "The provided URL is not a valid, absolute URL.";
            }
        }
    }
}
