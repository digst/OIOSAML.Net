using System;
using System.Collections.Generic;
using System.Text;
using dk.nita.saml2.ext.brs.schema;
using System.Diagnostics;
using Trace = dk.nita.saml20.Utils.Trace;
using dk.nita.saml20.ext.brs;
using dk.nita.saml20.Utils;
using System.Text.RegularExpressions;

namespace dk.nita.saml20.ext.brs
{
    internal class AuthorisationsParser
    {
        private string _productionUnitRegEx = @"urn\:dk\:cvr\:productionUnitIdentifier\:(\d+)";
        private string _cvrNumberRegEx = @"urn\:dk\:cvr\:cVRnumberIdentifier\:(\d{8})";

        private bool _isLoaded;

        private AuthorisationsType _autorisations;

        private AuthorisationsType Authorisations
        {
            get
            {
                if (!_isLoaded)
                {
                    Trace.TraceData(TraceEventType.Error, Errors.AuthorisationsNotLoaded);
                    throw new Saml20BRSException(Errors.AuthorisationsNotLoaded);
                }

                return _autorisations;
            }
        }

        public void Load(string base64AuthorisationsAttribute)
        {
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(base64AuthorisationsAttribute));
                AuthorisationsType authorisations = Serialization.DeserializeFromXmlString<AuthorisationsType>(decoded);
                _autorisations = authorisations;
                _isLoaded = true;
            }
            catch (Exception e)
            {
                _isLoaded = false;
                if(Trace.ShouldTrace(TraceEventType.Error))
                    Trace.TraceData(TraceEventType.Error, string.Format(Errors.DecodeFailed,base64AuthorisationsAttribute,e.Message));
                throw new Saml20BRSException(Errors.DecodeFailedMsg, e);
            }
        }

        public void Load(AuthorisationsType authorisations)
        {
            if (authorisations == null)
            {
                _isLoaded = false;
                throw new ArgumentException(Errors.LoadNullAuthorisations, "authorisations");
            }

            _autorisations = authorisations;
            _isLoaded = true;
        }

        public bool HasPrivilege(PrivilegeFor forType, string identifier, string privilegeName)
        {
            if (Authorisations.Authorisations == null || Authorisations.Authorisations.Count == 0)
                return false;

            string sre = string.Empty;

            switch(forType){
                case PrivilegeFor.CvrNumber:
                    sre = _cvrNumberRegEx;
                    break;
                case PrivilegeFor.ProductionUnit:
                    sre = _productionUnitRegEx;
                    break;
            }

            foreach (AuthorisationType at in Authorisations.Authorisations)
            {
                Regex re = new Regex(sre);
                if (re.IsMatch(at.resource))
                {
                    Match m = re.Match(at.resource);
                    string localIdentifier = m.Groups[1].Value;
                    if (localIdentifier == identifier)
                    {
                        if (at.Privilege != null && at.Privilege.Count > 0)
                        {
                            foreach (PrivilegeType pt in at.Privilege)
                            {
                                if (pt.Value == privilegeName)
                                    return true;                                     
                            }
                        }
                    }
                }
            }

            return false;
        }

        internal enum PrivilegeFor
        {
            CvrNumber,
            ProductionUnit,
        }
    }
}
