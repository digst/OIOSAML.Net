<%@ Page Language="C#" Title="Select certificate" MasterPageFile="~/idp.Master" AutoEventWireup="true" CodeBehind="CertificateSelection.aspx.cs" Inherits="IdentityProviderDemo.CertificateSelection" %>
<asp:Content ID="Content2" ContentPlaceHolderID="ContentPlaceHolder1" runat="server">
   <h2>Select the certificate to use for the identity provider</h2>
    <div>        
        <asp:DropDownList id="StoreLocationDropDown" runat="server" />&nbsp;
        <asp:DropDownList id="CertificateStoreDropDown" runat="server" />&nbsp;                
        
        <asp:Button id="ShowButton" runat="server" Text="Show certificates" /><br />
        <h3><asp:Label ID="messageLabel" runat="server" /></h3>
        <asp:Panel ID="CertificatePanel" runat="server" />        
    </div>
</asp:Content>