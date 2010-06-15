<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="MyPage.aspx.cs" Inherits="WebsiteDemoVirk.MyPage" MasterPageFile="~/sp.Master"%>
<%@ Import Namespace="WebsiteDemoVirk"%>

<%@ Import Namespace="dk.nita.saml20.identity" %>
<%@ Import Namespace="dk.nita.saml20.config" %>
<%@ Import Namespace="dk.nita.saml20.Schema.Core" %>

<asp:Content runat="server" ID="Content1" ContentPlaceHolderID="head">
    <style type="text/css">
        table
        {
            border-width: 1px;
            border-spacing: 2px;
            border-style: solid;
            border-color: black;
            border-collapse: collapse;
            background-color: white;
        }
        table th
        {
            border-width: 1px;
            padding: 3px;
            border-style: dotted;
            border-color: gray;
        }
        table td
        {
            border-width: 1px;
            padding: 3px;
            border-style: dotted;
            border-color: gray;
            background-color: white;
        }
    </style>
</asp:Content>
<asp:Content ID="Content2" runat="server" ContentPlaceHolderID="ContentPlaceHolder1">
    <% if (Saml20Identity.IsInitialized()) { %>
    <div>
        Welcome, <%= Saml20Identity.Current.Name + (Saml20Identity.Current.PersistentPseudonym != null ? " (Pseudonym is " + Saml20Identity.Current.PersistentPseudonym + ")" : String.Empty)%><br />
        <table style="border: solid 1px;">
            <thead>
                <tr>
                    <th>
                        Attribute name
                    </th>
                    <th>
                        Attribute value
                    </th>
                </tr>
            </thead>
            <% foreach (SamlAttribute att in Saml20Identity.Current)
               { %>
            <tr>
                <td>
                    <%= att.Name %>
                </td>
                <td>
                    <%= att.AttributeValue.Length > 0 ? att.AttributeValue[0] : string.Empty %>
                </td>
            </tr>
            <%  } %>
        </table>
    </div>
    <asp:Panel ID="BrsPanel" runat="server"></asp:Panel>
    <asp:Panel ID="StatusPanel" runat="server"></asp:Panel>
    <% } %>

    <div><a href="logout.ashx">Logout</a></div>
</asp:Content>
