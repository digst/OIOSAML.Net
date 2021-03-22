<%@ Page Language="C#" AutoEventWireup="true" EnableEventValidation="false" CodeBehind="SignonForm.aspx.cs" MasterPageFile="~/idp.Master" Inherits="IdentityProviderDemo.SignonForm" %>

<asp:Content ID="Content2" ContentPlaceHolderID="ContentPlaceHolder1" runat="server">
    <div class="position: relative">
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
            <span>Level of assurance :</span>
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

        <div style="border: 1px solid grey; display: block; width: auto; padding: 5px 15px;" runat="server" id="DemandArea" visible="false">
            <div style="font-weight: bold">The Service Provider has the following demands:</div>
            <asp:Label runat="server" ID="SPDesiredContext"></asp:Label>
        </div>

        <div style="border: 1px solid grey; display: block; width: auto; padding: 5px 15px;">
            <div ><span style="font-weight: bold">Default users are:</span> Username <span style="color: gray">(Password)</span></div>
            <ul>
                <% foreach (var user in Users)
                    { %>
                <li><%= user.Key %> <span style="color: gray">(<%= user.Value.Password %>)</span> - <%= user.Value.Profile %></li>
                <% } %>
            </ul>

        </div>

        <div>
            <asp:Label runat="server" ID="MessageLbl" />
        </div>
    </div>
</asp:Content>
