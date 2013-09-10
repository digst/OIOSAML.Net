using System;
using System.Web.UI;

namespace IdentityProviderDemo
{
    /// <summary>
    /// Redirects to the control panel of the identity provider.
    /// </summary>
    public partial class Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            Context.Response.Redirect("Control.aspx");
        }
    }
}
