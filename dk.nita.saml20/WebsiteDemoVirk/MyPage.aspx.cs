using System;
using System.Configuration;
using System.Web.UI;
using System.Web.UI.WebControls;
using dk.nita.saml20;
using dk.nita.saml20.config;
using dk.nita.saml20.ext.brs;

namespace WebsiteDemoVirk
{
    public partial class MyPage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {            
            Title = "My page on SP " + SAML20FederationConfig.GetConfig().ServiceProvider.ID;
        }

        private string privilegeDropDownId = "PrivilegeDropDown";
        private string unitTypeDropDownId = "UnitTypeDropDown";
        private string typeIdTextBoxId = "TypeIdTextBox";

        private const string unitTypeCvr = "Cvr number";
        private const string unitTypeProdUnit = "Production unit";

        protected override void CreateChildControls()
        {
            base.CreateChildControls();

            BrsPanel.Controls.Add(LC("<br/>This page lets you test if the currently logged in user has a given privilege for a given organisation.<br/>"));
            BrsPanel.Controls.Add(LC("<b>Please note that the demo IdP does not issue Authorisations attributes, and therefore you should not expect the user to have any privileges before you have succesfully connected to virk.dk's integration test IdP.</b><br/><br/>"));

            BrsPanel.Controls.Add(LC("<hr/>"));

            BrsPanel.Controls.Add(LC("You must perform an attribute query to get the Authorisations attribute from the virk.dk IdP.</b> <br/>Use the following button to do so:"));
            Button b = new Button();
            b.Text = "Perform attr. query";
            b.Click += b_Click;

            BrsPanel.Controls.Add(b);
            BrsPanel.Controls.Add(LC(@"<span style=""color:red;"">This operation is NOT supported by the Demo IdP.</span><br/><br/>"));

            string privs = ConfigurationManager.AppSettings["KnownPrivileges"];

            BrsPanel.Controls.Add(LC("Choose privilege: "));

            DropDownList ddl = new DropDownList();
            ddl.ID = privilegeDropDownId;
            foreach(string s in privs.Split(';'))
            {
                ddl.Items.Add(s);
            }

            BrsPanel.Controls.Add(ddl);

            BrsPanel.Controls.Add(LC(" choose type: "));

            DropDownList ddl2 = new DropDownList();
            ddl2.ID = unitTypeDropDownId;
            ddl2.Items.Add(unitTypeCvr);
            ddl2.Items.Add(unitTypeProdUnit);

            BrsPanel.Controls.Add(ddl2);

            BrsPanel.Controls.Add(LC(" number: "));

            TextBox tbx = new TextBox();
            tbx.ID = typeIdTextBoxId;

            BrsPanel.Controls.Add(tbx);

            Button check = new Button();
            check.Text = "Check now";
            check.Click += check_Click;

            BrsPanel.Controls.Add(check);

            BrsPanel.Controls.Add(LC("<hr/>"));
        }

        void check_Click(object sender, EventArgs e)
        {
            BRSUtil util = new BRSUtil();

            DropDownList ddl = BrsPanel.FindControl(privilegeDropDownId) as DropDownList;
            string privilege = ddl.SelectedValue;

            DropDownList ddl2 = BrsPanel.FindControl(unitTypeDropDownId) as DropDownList;
            string unitType = ddl2.SelectedValue;

            TextBox tbx = BrsPanel.FindControl(typeIdTextBoxId) as TextBox;
            string id = tbx.Text;

            StatusPanel.Controls.Add(LC(string.Format("Checking privilege \"{0}\" for id \"{2}\" ({1}).", privilege, unitType, id)));

            StatusPanel.Controls.Add(LC("Result: "));

            if(util.HasAuthorisationAttribute())
            {
                bool hasIt = false;

                switch(unitType)
                {
                    case unitTypeCvr:
                        hasIt = util.HasPrivilegeForCvrNumber(id, privilege);
                        break;
                    case unitTypeProdUnit:
                        hasIt = util.HasPrivilegeForProductionUnit(id, privilege);
                        break;
                }

                if(hasIt)
                {
                    StatusPanel.Controls.Add(Green("The user has it!"));
                }else
                {
                    StatusPanel.Controls.Add(Red("The user does not have it!"));
                }

            }else
            {
                StatusPanel.Controls.Add(Red("No Authorisations attribute present."));
            }

        }

        void b_Click(object sender, EventArgs e)
        {
            Saml20AttributeQuery q = Saml20AttributeQuery.GetDefault();
            q.PerformQuery(Context);
        }

        private LiteralControl Red(string text)
        {
            return LC(string.Format("<span style=\"color:red\">{0}</span>", text));
        }

        private LiteralControl Green(string text)
        {
            return LC(string.Format("<span style=\"color:green\">{0}</span>", text));
        }

        private LiteralControl LC(string text)
        {
            return new LiteralControl(text);
        }
    }
}