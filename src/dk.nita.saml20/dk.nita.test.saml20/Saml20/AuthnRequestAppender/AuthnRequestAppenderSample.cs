using System.Web;
using dk.nita.saml20;
using dk.nita.saml20.AuthnRequestAppender;

namespace dk.nita.test.Saml20.AuthnRequestAppender
{
    /// <summary>
    /// Just a sample implementation of IAuthnRequestAppender to verify that AuthnRequestAppenderFactory works
    /// </summary>
    public class AuthnRequestAppenderSample : IAuthnRequestAppender
    {
        public void AppendAction(Saml20AuthnRequest authnRequest, HttpRequest request)
        {
        }
    }
}