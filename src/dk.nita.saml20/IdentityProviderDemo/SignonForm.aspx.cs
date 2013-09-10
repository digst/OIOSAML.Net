using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;
using IdentityProviderDemo.config;
using IdentityProviderDemo.Logic;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Bindings;
using dk.nita.saml20.Utils;

namespace IdentityProviderDemo
{
    public partial class SignonForm : Page
    {                        
        private AuthnRequest request;

        protected override void OnInit(EventArgs e)
        {            
            request = Context.Application["authenticationrequest"] as AuthnRequest;

            if (request == null)
            {
                HandleRequestMissing();
                return; 
            }

            User user = UserSessionsHandler.CurrentUser;
            
            if (user != null)
            {
                // don't issue new assertion if ForceAuthn is set
                if (request.ForceAuthn.HasValue && request.ForceAuthn.Value)
                    return;

                // User has a previous session on the IDP. Issue a new assertion.
                CreateAssertionResponse(user);
            }
        }

        private void HandleRequestMissing()
        {
            Context.Response.Write("This page cannot be accessed directly.");
            Context.Response.End();            
        }

        protected void Page_Load(object sender, EventArgs e)
        {}

        protected void AuthenticateUser(object sender, EventArgs e)
        {
            MessageLbl.Text = string.Empty;
            if (!UserData.Users.ContainsKey(UsernameTextbox.Text))
            {
                ErrorLabel.Text = "Unknown user";
                ErrorLabel.Visible = true;
                return;
            }

            User user = UserData.Users[UsernameTextbox.Text];
            if (user.Password != PasswordTestbox.Text)
            {
                ErrorLabel.Text = "Bad password";
                ErrorLabel.Visible = true;
                return;
            }
            else
            {
                UserSessionsHandler.CurrentUser = user;
                WriteCommonDomainCookie();
                CreateAssertionResponse(user);
                return;
            }
        }

        private void CreateAuthenticationFailedResponse()
        {
            string entityId = request.Issuer.Value;
            Saml20MetadataDocument metadataDocument = IDPConfig.GetServiceProviderMetadata(entityId);
            IDPEndPointElement endpoint =
                metadataDocument.AssertionConsumerServiceEndpoints().Find(delegate(IDPEndPointElement e) { return e.Binding == SAMLBinding.POST; });

            if (endpoint == null)
            {
                Context.Response.Write(string.Format("'{0}' does not have a SSO endpoint that supports the POST binding.", entityId));
                Context.Response.End();
                return;
            }

            Response response = new Response();
            response.Destination = endpoint.Url;
            response.Status = new Status();
            response.Status.StatusCode = new StatusCode();
            response.Status.StatusCode.Value = Saml20Constants.StatusCodes.Requester;

            response.Status.StatusCode.SubStatusCode = new StatusCode();
            response.Status.StatusCode.SubStatusCode.Value = Saml20Constants.StatusCodes.AuthnFailed;
            response.Status.StatusMessage = "Authentication failed. Username and/or password was incorrect.";

            HttpPostBindingBuilder builder = new HttpPostBindingBuilder(endpoint);
            builder.Action = SAMLAction.SAMLResponse;
            builder.Response = Serialization.SerializeToXmlString(response);

            builder.GetPage().ProcessRequest(Context);
            Context.Response.End();            
        }

        private void CreateAssertionResponse(User user)
        {
            string entityId = request.Issuer.Value;
            Saml20MetadataDocument metadataDocument = IDPConfig.GetServiceProviderMetadata(entityId);
            IDPEndPointElement endpoint =
                metadataDocument.AssertionConsumerServiceEndpoints().Find(delegate(IDPEndPointElement e) { return e.Binding == SAMLBinding.POST; });

            if (endpoint == null)
            {
                Context.Response.Write(string.Format("'{0}' does not have a SSO endpoint that supports the POST binding.", entityId));
                Context.Response.End();
                return;
            }

            UserSessionsHandler.AddLoggedInSession(entityId);

            Response response = new Response();
            response.Destination = endpoint.Url;
            response.InResponseTo = request.ID;
            response.Status = new Status();
            response.Status.StatusCode = new StatusCode();
            response.Status.StatusCode.Value = Saml20Constants.StatusCodes.Success;

            Assertion assertion = CreateAssertion(user, entityId);
            response.Items = new object[] { assertion };

            // Serialize the response.
            XmlDocument assertionDoc = new XmlDocument();
            assertionDoc.PreserveWhitespace = true;
            assertionDoc.LoadXml(Serialization.SerializeToXmlString(response));

            // Sign the assertion inside the response message.
            XmlSignatureUtils.SignDocument(assertionDoc, assertion.ID, IDPConfig.IDPCertificate);
            
            HttpPostBindingBuilder builder = new HttpPostBindingBuilder(endpoint);
            builder.Action = SAMLAction.SAMLResponse;
            builder.Response = assertionDoc.OuterXml;

            builder.GetPage().ProcessRequest(Context);
            Context.Response.End();
        }

        private void WriteCommonDomainCookie()
        {
            string cookieValue = HttpUtility.UrlEncode(Convert.ToBase64String(Encoding.ASCII.GetBytes(IDPConfig.ServerBaseUrl)));

            HttpCookie cdc = new HttpCookie(CommonDomainCookie.COMMON_DOMAIN_COOKIE_NAME, cookieValue);
            cdc.Domain = "." + Context.Request.Url.Host;
            Context.Response.Cookies.Add(cdc);
        }

        private Assertion CreateAssertion(User user, string receiver)
        {
            Assertion assertion = new Assertion();
                        
            { // Subject element                
                assertion.Subject = new Subject();
                assertion.ID = "id" + Guid.NewGuid().ToString("N");
                assertion.IssueInstant = DateTime.Now.AddMinutes(10);
                
                assertion.Issuer = new NameID();
                assertion.Issuer.Value = IDPConfig.ServerBaseUrl;

                SubjectConfirmation subjectConfirmation = new SubjectConfirmation();
                subjectConfirmation.Method = SubjectConfirmation.BEARER_METHOD;
                subjectConfirmation.SubjectConfirmationData = new SubjectConfirmationData();
                subjectConfirmation.SubjectConfirmationData.NotOnOrAfter = DateTime.Now.AddHours(1);
                subjectConfirmation.SubjectConfirmationData.Recipient = receiver;

                NameID nameId = new NameID();
                nameId.Format = Saml20Constants.NameIdentifierFormats.Persistent;
                nameId.Value = user.ppid;
                
                assertion.Subject.Items = new object[] { nameId, subjectConfirmation };
            }

            { // Conditions element
                assertion.Conditions = new Conditions();
                assertion.Conditions.Items = new List<ConditionAbstract>();

                assertion.Conditions.NotOnOrAfter = DateTime.Now.AddHours(1);

                AudienceRestriction audienceRestriction = new AudienceRestriction();                
                audienceRestriction.Audience = new List<string>();
                audienceRestriction.Audience.Add(receiver);
                assertion.Conditions.Items.Add(audienceRestriction);
            }

            List<StatementAbstract> statements = new List<StatementAbstract>(2);
            { // AuthnStatement element
                AuthnStatement authnStatement = new AuthnStatement();
                authnStatement.AuthnInstant = DateTime.Now;
                authnStatement.SessionIndex = Convert.ToString(new Random().Next());
                
                authnStatement.AuthnContext = new AuthnContext();

                authnStatement.AuthnContext.Items = 
                    new object[] {"urn:oasis:names:tc:SAML:2.0:ac:classes:X509"};

                // Wow! Setting the AuthnContext is .... verbose.
                authnStatement.AuthnContext.ItemsElementName =
                    new ItemsChoiceType5[] { ItemsChoiceType5.AuthnContextClassRef };
                                    
                statements.Add(authnStatement);
            }

            { // Generate attribute list.                
                AttributeStatement attributeStatement = new AttributeStatement();

                List<SamlAttribute> attributes = new List<SamlAttribute>(user.Attributes.Count);
                foreach (KeyValuePair<string, string> att in user.Attributes)
                {
                    SamlAttribute attribute = new SamlAttribute();
                    attribute.Name = att.Key;
                    attribute.AttributeValue = new string[] { att.Value };
                    attribute.NameFormat = SamlAttribute.NAMEFORMAT_BASIC;
                    attributes.Add(attribute);
                }
                attributeStatement.Items = attributes.ToArray();

                statements.Add(attributeStatement);
            }

            assertion.Items = statements.ToArray();

            return assertion;
        }
    }
}
