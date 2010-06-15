using System;
using System.Collections.Generic;
using System.Text;
using dk.nita.saml2.ext.brs.Profiles.DKSaml20.Attributes;
using dk.nita.saml20.Utils;
using dk.nita.saml20.identity;

namespace dk.nita.saml20.ext.brs
{
    public class BRSUtil
    {
        public Saml20Identity CurrentIdentity
        {
            get
            {
                if(Saml20Identity.Current == null)
                {
                    Trace.TraceData(System.Diagnostics.TraceEventType.Error, Errors.NoSaml20Identity);
                    throw new Saml20BRSException(Errors.NoSaml20Identity);
                }

                return Saml20Identity.Current;
            }
        }

        private AuthorisationsParser _parser;

        private AuthorisationsParser Parser
        {
            get
            {
                if (_parser == null)
                {
                    if (!HasAuthorisationAttribute())
                    {
                        Trace.TraceData(System.Diagnostics.TraceEventType.Error, Errors.NoAuthorisationsAttribute);
                        throw new Saml20BRSException(Errors.NoAuthorisationsAttribute);
                    }

                    _parser = new AuthorisationsParser();
                    _parser.Load(CurrentIdentity[DKSaml20AuthorisationsAttribute.NAME][0].AttributeValue[0]);
                }

                return _parser;
            }
        }

        public bool HasPrivilegeForCvrNumber(string cvrNumber, string privilege)
        {
            if (!HasAuthorisationAttribute())
                return false;

            return Parser.HasPrivilege(AuthorisationsParser.PrivilegeFor.CvrNumber, cvrNumber, privilege);
        }

        public bool HasPrivilegeForProductionUnit(string productionUnit, string privilege)
        {
            if (!HasAuthorisationAttribute())
                return false;

            return Parser.HasPrivilege(AuthorisationsParser.PrivilegeFor.ProductionUnit, productionUnit, privilege);
        }

        public bool HasAuthorisationAttribute()
        {
            return CurrentIdentity.HasAttribute(DKSaml20AuthorisationsAttribute.NAME);
        }
    }
}
