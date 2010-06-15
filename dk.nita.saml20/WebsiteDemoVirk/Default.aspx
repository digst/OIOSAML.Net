<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" MasterPageFile="~/sp.Master" Inherits="WebsiteDemo._Default" %>
<%@ Import namespace="dk.nita.saml20.config"%>
<asp:Content ID="Content2" ContentPlaceHolderID="ContentPlaceHolder1" runat="server">
    <div>
        <a href="MyPage.aspx">Go to My Page.</a>
    </div>
    <div style="margin-top: 1em; ">
        <h3>Metadata</h3>
        <p style="width: 50em;">
        The identity provider and the service provider must exchange metadata in order to establish SAML connections. 
        <% if (string.IsNullOrEmpty(SAML20FederationConfig.GetConfig().Endpoints.metadataLocation)) { %>
            You must add the <b>&lt;IDPEndPoints&gt;</b> tag to the <b>"<%= ConfigurationConstants.SectionNames.SAML20Federation %>"</b> section of the
            application's configuration file in order to continue.
        <% } else if (certificateMissing) { %>
            <div style="color: Red;">
            The specified certificate could not be found. Please correct 
            the certificate information in the "<%= ConfigurationConstants.SectionNames.Federation %>" section of the configuration file.
            </div>
        <% } else { %>
            The Identity provider's metadata should be put in the directory <b>"<%= SAML20FederationConfig.GetConfig().Endpoints.metadataLocation %>"</b>.<br/><br/>
            The metadata of the service provider can be downloaded <a href="metadata.ashx">here</a>.
            <br /><br />
            <b>This Service Provider is intended to demonstrate integration to virk.dk and how to use the Authorisations attribute</b>.
        <% } %>
                
        </p>           
    </div>
</asp:Content>
