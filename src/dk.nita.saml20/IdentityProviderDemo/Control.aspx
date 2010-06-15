<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Control.aspx.cs" Inherits="IdentityProviderDemo.Control" MasterPageFile="~/idp.Master" %>
<%@ Import namespace="IdentityProviderDemo.Logic"%>
<asp:Content ID="Content2" ContentPlaceHolderID="ContentPlaceHolder1" runat="server">
<asp:Panel ID="SetupPanel" runat="server" Visible="false"></asp:Panel>
<asp:Panel ID="ReadyPanel" runat="server" Visible="false">
    <div>The Identity Provider is ready to accept transactions. (<a href="MetadataIssuer.ashx">Download metadata</a>)</div>
    
    
    <%if (IDPConfig.ServiceProviderCount == 0) { %>
        <div>It is currently not configured to talk to any service providers. Please add metadata for at least one service provider.</div>
    <%} else { %>
        <div>It is currently configured to accept requests from the following service providers<br />
            <asp:Panel ID="ServiceProviderList" runat="server" />            
        </div>       
    <%  } %>
            
        <asp:FileUpload runat="server" ID="_fileupload" />    
        <asp:Button ID="Button1" runat="server" Text="Upload metadata" OnClick="UploadButton_Click" /><br />
        <div><asp:Label runat="server" id="_statusLabel" /></div>
        <div>
        <asp:Label runat="server" ID="certLabel"></asp:Label>
        <asp:Button runat="server" ID="ClearCert" Text="Change certificate" OnClick="ClearCert_Click" />
        </div>
        <div>
        <asp:Label runat="server" ID="baseUrlLabel"></asp:Label>
        <asp:Button runat="server" ID="ChangeBaseUrl" Text="Change Base Url" OnClick="ChangeBaseUrl_Click" />
        </div>
</asp:Panel>
        
</asp:Content>

