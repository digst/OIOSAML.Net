<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="MyPage.aspx.cs" Inherits="WebsiteDemo.WebForm1" MasterPageFile="~/sp.Master" %>

<%@ Import Namespace="dk.nita.saml20.identity" %>
<%@ Import Namespace="dk.nita.saml20.config" %>
<%@ Import Namespace="dk.nita.saml20.Schema.Core" %>
<%@ Import Namespace="dk.nita.saml20.Profiles.BasicPrivilegeProfile" %>

<asp:Content runat="server" ID="Content1" ContentPlaceHolderID="head">
    <style type="text/css">
        table {
            border-width: 1px;
            border-spacing: 2px;
            border-style: solid;
            border-color: black;
            border-collapse: collapse;
            background-color: white;
        }

            table th {
                border-width: 1px;
                padding: 3px;
                border-style: dotted;
                border-color: gray;
            }

            table td {
                border-width: 1px;
                padding: 3px;
                border-style: dotted;
                border-color: gray;
                background-color: white;
            }
    </style>
</asp:Content>
<asp:Content ID="Content2" runat="server" ContentPlaceHolderID="ContentPlaceHolder1">

    <% if (Saml20Identity.IsInitialized())
        { %>
    <div>
        Welcome, <%= Saml20Identity.Current.Name %><br />
        <h1>SAML attributes</h1>
        <table style="border: solid 1px;">
            <thead>
                <tr>
                    <th>Attribute name
                    </th>
                    <th>Attribute value
                    </th>
                </tr>
            </thead>
            <% foreach (SamlAttribute att in Saml20Identity.Current)
                {
                    foreach (string attVal in att.AttributeValue)
                    {
            %>
            <tr>
                <td style="vertical-align: top">
                    <%= att.Name %>
                </td>
                <td style="word-break: break-word;">
                    <%= att.AttributeValue.Length > 0 ? Server.HtmlEncode(attVal) : string.Empty %>
                </td>
            </tr>
            <% }
                } %>
        </table>

        <% if (Saml20Identity.Current.BasicPrivilegeProfile.Any())
            { %>
        <h1>Basic Privilege Profile</h1>
        <table style="border: solid 1px;">
            <thead>
                <tr>
                    <th>Scope
                    </th>
                    <th>Privilege
                    </th>
                    <th>Constraints</th>
                </tr>
            </thead>
            <% foreach (Privilege att2 in Saml20Identity.Current.BasicPrivilegeProfile)
                { %>
            <tr>
                <td>
                    <%= att2.Scope %>
                </td>
                <td>
                    <%= att2.Value %>
                </td>
                <td><%= (att2.Constraints != null) ? string.Join("<br />", att2.Constraints.Select(x => x.Name + ": " + x.Value)) : ""  %></td>
            </tr>
            <%  } %>
        </table>
        <% } %>
    </div>
    <% } %>

    <div>
        <asp:Button Style="margin-top: 10px;" ID="btnLogoff" runat="server" Enabled="true" Text="Logoff" OnClick="Btn_Logoff_Click" />
    </div>
    <br />
    <div>
        Relogin with IdP: 
    <asp:Button ID="Btn_Relogin" runat="server" Enabled="true" Text="ForceAuthn" OnClick="Btn_Relogin_Click" />
        <asp:Button ID="Btn_Passive" runat="server" Enabled="true" Text="Passive login" OnClick="Btn_Passive_Click" />
        <asp:Button ID="Btn_ReloginNoForceAuthn" runat="server" Enabled="true" Text="No ForceAuthn" OnClick="Btn_ReloginNoForceAuthn_Click" />

    </div>
</asp:Content>
