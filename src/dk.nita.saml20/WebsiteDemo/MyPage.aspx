<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="MyPage.aspx.cs" Inherits="WebsiteDemo.WebForm1" MasterPageFile="~/sp.Master"%>

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
    <% if (int.Parse(Saml20Identity.Current["dk:gov:saml:attribute:AssuranceLevel"][0].AttributeValue[0]) < 3)
       {
           throw new Exception("Saml assertion does not have required assurance level.");
       }%>
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
    <% } %>

    <div><asp:Button Id="btnLogoff" runat="server" Enabled="true" Text="Logoff" OnClick="Btn_Logoff_Click" /></div>
    <br />
    <div>Relogin with IdP: <asp:Button Id="Btn_Relogin" runat="server" Enabled="true" Text="ForceAuthn" OnClick="Btn_Relogin_Click" />
    <asp:Button Id="Btn_ReloginNoForceAuthn" runat="server" Enabled="true" Text="No ForceAuthn" OnClick="Btn_ReloginNoForceAuthn_Click" />
    
    </div>
</asp:Content>
