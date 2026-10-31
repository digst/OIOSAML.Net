using System;
using System.Web;
using System.Web.UI;
using Saml2.Properties;

namespace dk.nita.saml20.protocol.pages
{
    /// <summary>
    /// A page for displaying error messages
    /// </summary>
    public class ErrorPage : BasePage
    {
        #region Constructor functions

        /// <summary>
        /// Initializes a new instance of the <see cref="ErrorPage"/> class.
        /// </summary>
        public ErrorPage()
        {
            TitleText = Resources.Error;
            HeaderText = Resources.Error;
        }

        #endregion

        #region Properties

        private string _errorText = string.Empty;

        /// <summary>
        /// Gets or sets the error text: plain text, HTML-encoded by the page; line breaks are kept.
        /// </summary>
        /// <value>The error text.</value>
        public string ErrorText
        {
            get { return _errorText; }
            set { _errorText = value; }
        }

        private bool _overrideConfig = false;

        /// <summary>
        /// Ignored: the page always follows the customErrors setting.
        /// </summary>
        [Obsolete("Ignored: the error page always follows the customErrors setting.")]
        public bool OverrideConfig
        {
            get { return _overrideConfig; }
            set { _overrideConfig = value; }
        }

        #endregion

        #region overridden page functions

        /// <summary>
        /// Raises the <see cref="E:System.Web.UI.Control.Load"/> event.
        /// </summary>
        /// <param name="e">The <see cref="T:System.EventArgs"/> object that contains the event data.</param>
        protected override void OnLoad(EventArgs e)
        {
            var err = Context.IsCustomErrorEnabled ? Resources.GenericError : _errorText;
            BodyPanel.Controls.Add(new LiteralControl(ToHtml(err)));

        }

        #endregion

        /// <summary>
        /// The error text as HTML: encoded, with its line breaks kept.
        /// </summary>
        internal static string ToHtml(string text)
        {
            return HttpUtility.HtmlEncode(text ?? string.Empty).Replace("\r\n", "\n").Replace("\n", "<br />");
        }
    }
}
