using System.Web;

namespace dk.nita.saml20.AuthnRequestAppender
{
    /// <summary>
    /// An implementation of the IAuthnRequestAppender interface is instantiated and called if configured in FederationConfig.
    /// This can be used to append additional elements to the AuthnRequest just before it is signed and transferred. 
    /// </summary>
    public interface IAuthnRequestAppender
    {
        /// <summary>
        /// Action to perform on the AuthnRequest before transfer is performed
        /// This can be used to add/update elements on the authnRequest
        /// </summary>
        /// <param name="authnRequestToUpdate">The authnRequest to update</param>
        /// <param name="request">the initial request that triggered the generation of the AuthnRequest.</param>
        void AppendAction(Saml20AuthnRequest authnRequestToUpdate, HttpRequest request);
    }
}