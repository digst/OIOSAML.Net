using System.Collections.Generic;
using System.Configuration;
using System;

namespace IdentityProviderDemo.Logic
{
    /// <summary>
    /// Holds data on the users that can be authenticated with the identity provider.
    /// It is a quick-fix solution to have this in code. Someone should spend a few hours on putting this data in
    /// an xml-file somewhere.
    /// </summary>
    public class UserData
    {

        /// <summary>
        /// A dictionary containing (username, users) sets.
        /// </summary>
        public static Dictionary<string, User> Users = new Dictionary<string, User>();

        static UserData()
        {


            DemoIdPConfigurationSection config = (DemoIdPConfigurationSection)ConfigurationManager.GetSection("demoIdp");
            foreach (User u in config.Users)
            {
                UserData.Users.Add(u.Username, u);
            }


        }
    }

    public class User : ConfigurationElement
    {
        public User()
        {
        }

        public User(string Username, string Password, string PPID)
            : this()
        {
            this.Username = Username;
            this.Password = Password;
            this.ppid = PPID;
        }

        [ConfigurationProperty("userName")]
        public string Username
        {
            get { return (string)base["userName"]; }
            set { base["userName"] = value; }
        }

        [ConfigurationProperty("password")]
        public string Password
        {
            get { return (string)base["password"]; }
            set { base["password"] = value; }
        }

        [ConfigurationProperty("ppid")]
        public string ppid
        {
            get { return (string)base["ppid"]; }
            set { base["ppid"] = value; }
        }

        [ConfigurationProperty("attributes", IsDefaultCollection = false)]
        public AttributeCollection ConfiguredAttributes
        {
            get { return (AttributeCollection)base["attributes"]; }
        }

        public List<KeyValuePair<string, string>> Attributes
        {
            get 
            {
                List<KeyValuePair<string, string>> returnValue = new List<KeyValuePair<string, string>>();
                foreach (Attribute a in this.ConfiguredAttributes)
                {
                    returnValue.Add(new KeyValuePair<string, string>(a.Name, a.Value));
                }
                return returnValue;
            }
        }
    }

    public class DemoIdPConfigurationSection : ConfigurationSection
    {
        [ConfigurationProperty("users", IsDefaultCollection = false)]
        public UserCollection Users
        {
            get { return (UserCollection)base["users"]; }
        }
    }

    public class UserCollection : ConfigurationElementCollection
    {
        protected override ConfigurationElement CreateNewElement()
        {
            return new User();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((User)element).Username;
        }
    }

    public class Attribute : ConfigurationElement
    {
        [ConfigurationProperty("name")]
        public string Name
        {
            get { return (string)base["name"]; }
            set { base["name"] = value; }
        }

        [ConfigurationProperty("value")]
        public string Value
        {
            get { return (string)base["value"]; }
            set { base["value"] = value; }
        }

        public string Key
        {
            get { return this.Name + this.Value; }
        }
    }

    public class AttributeCollection : ConfigurationElementCollection
    {
        protected override ConfigurationElement CreateNewElement()
        {
            return new Attribute();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((Attribute)element).Key;
        }
    }

}