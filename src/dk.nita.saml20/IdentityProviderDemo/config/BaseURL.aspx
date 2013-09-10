<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="BaseURL.aspx.cs" Inherits="IdentityProviderDemo.BaseURL" MasterPageFile="~/idp.Master" Title="Specify base url" %>
<asp:Content ID="Content2" ContentPlaceHolderID="ContentPlaceHolder1" runat="server">
    <h2>Specify the base URL for the endpoints of the identity provider.</h2>    
    <div style="width: 40em; margin-bottom: 10px;">
    The initial value is a guess based on the address used to access this page. If the address contains <b>localhost</b> or <b>127.0.0.1</b> as the server address it is not usable. 
    </div>
    <div>
        <asp:TextBox ID="baseurl" runat="server" Columns="80" />
        <asp:Button ID="submitButton" runat="server" Text="Ok" />
    </div>
    <div style="margin-top: 10px;">
        <b><asp:Label ID="MessageLabel" runat="server" /></b>
    </div>
</asp:Content>

