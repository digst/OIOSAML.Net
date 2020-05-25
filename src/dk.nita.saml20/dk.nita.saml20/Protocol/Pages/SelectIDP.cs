using System;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using dk.nita.saml20.config;
using Saml2.Properties;

namespace dk.nita.saml20.protocol.pages
{
    /// <summary>
    /// Page that handles selecting an IdP when more than one is configured
    /// </summary>
    public class SelectSaml20IDP : BasePage
    {
        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Load"/> event.
        /// </summary>
        /// <param name="e">The <see cref="T:System.EventArgs"/> object that contains the event data.</param>
        protected override void OnLoad(EventArgs e)
        {
            TitleText = Resources.ChooseIDP;
            HeaderText = Resources.ChooseIDP;
            
            BodyPanel.Controls.Add(new LiteralControl(Resources.ChooseDesc));
            BodyPanel.Controls.Add(new LiteralControl("<br/><br/>"));
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();
            
            foreach (IDPEndPoint endPoint in config.IDPEndPoints)
            {
                if (endPoint.metadata != null)
                {
                    HyperLink link = new HyperLink();

                    // Link text. If a name has been specified in web.config, use it. Otherwise, use id from metadata.
                    link.Text = string.IsNullOrEmpty(endPoint.Name) ? endPoint.metadata.EntityId : endPoint.Name;

                    string forceAuthnAsString = HttpContext.Current.Request.Params[Saml20SignonHandler.IDPForceAuthn];
                    bool forceAuthn;
                    bool.TryParse(forceAuthnAsString, out forceAuthn);

                    string isPassiveAsString = HttpContext.Current.Request.Params[Saml20SignonHandler.IDPIsPassive];
                    bool isPassive;
                    bool.TryParse(isPassiveAsString, out isPassive);

                    string desiredNSIS = HttpContext.Current.Request.Params[Saml20SignonHandler.LevelOfAssurance];
                    string desiredProfile = HttpContext.Current.Request[Saml20SignonHandler.Profile];

                    link.NavigateUrl = endPoint.GetIDPLoginUrl(forceAuthn, isPassive, desiredNSIS, desiredProfile);
                    BodyPanel.Controls.Add(link);
                    BodyPanel.Controls.Add(new LiteralControl("<br/>"));
                } else
                {
                    Label label = new Label();                               
                    label.Text = endPoint.Name;
                    label.Style.Add(HtmlTextWriterStyle.TextDecoration, "line-through");
                    BodyPanel.Controls.Add(label);

                    label = new Label();
                    label.Text = " (Metadata not found)";
                    label.Style.Add(HtmlTextWriterStyle.FontSize, "x-small");
                    BodyPanel.Controls.Add(label);

                    BodyPanel.Controls.Add(new LiteralControl("<br/>"));
                }
            }
        }
    }
}