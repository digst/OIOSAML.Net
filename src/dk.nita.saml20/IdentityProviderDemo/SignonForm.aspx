<%@ Page Language="C#" AutoEventWireup="true" EnableEventValidation="false" CodeBehind="SignonForm.aspx.cs" MasterPageFile="~/idp.Master" Inherits="IdentityProviderDemo.SignonForm" %>

<asp:Content ID="Content2" ContentPlaceHolderID="ContentPlaceHolder1" runat="server">
    <asp:Label runat="server" ID="ErrorLabel" Visible="false" ForeColor="Red"></asp:Label>
    <div>
        <span>Username : </span>
        <asp:TextBox ID="UsernameTextbox" runat="server" />
    </div>
    <div>
        <span>Password : </span>
        <asp:TextBox ID="PasswordTestbox" TextMode="Password" runat="server" />
    </div>
    <div>
        <span>Level of assurance :
            <asp:Label runat="server" ID="DesiredLoaLabel"></asp:Label></span>
        <div>
            <asp:RadioButton ID="LoaLegacy" runat="server" GroupName="LOA" Text="3 (OIOSAML 2 profile)" />
            <asp:RadioButton ID="LoaLow" runat="server" GroupName="LOA" Text="Low" />
            <asp:RadioButton ID="LoaSubstantial" runat="server" GroupName="LOA" Text="Substantial" Checked="true" />
            <asp:RadioButton ID="LoaHigh" runat="server" GroupName="LOA" Text="High" />
        </div>
    </div>
    <div>
        <asp:Button runat="server" Text="Login" OnClick="AuthenticateUser" />
    </div>
    <div>
        <asp:Label runat="server" ID="MessageLbl" />
    </div>
</asp:Content>
