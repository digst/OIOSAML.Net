using System.Configuration;
using System.IO;
using System.Web;

namespace IdentityProviderDemo.Logic
{
    public class ConfigHelper
    {
        public static string GetIdpDataDirectory()
        {
            var dir = ConfigurationManager.AppSettings["IDPDataDirectory"];

            if (dir != null && !Path.IsPathRooted(dir))
            {
                return Path.Combine(HttpContext.Current.Server.MapPath("/"), dir);
            }

            return dir;
        }
    }
}