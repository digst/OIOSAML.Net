using System;
using dk.nita.saml20.Profiles.DKSaml20;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Protocol;

namespace dk.nita.saml20.Validation
{
    internal class DKSaml20AttributeValidator : ISaml20AttributeValidator
    {
        public void ValidateAttribute(SamlAttribute samlAttribute)
        {            
            if (!Uri.IsWellFormedUriString(samlAttribute.Name, UriKind.Absolute))
                throw new DKSaml20FormatException("The DK-SAML 2.0 profile requires that an attribute's \"Name\" is an URI.");

            if (samlAttribute.AttributeValue == null)
                return;

            foreach (object val in samlAttribute.AttributeValue)
            {
                if (val is string)
                    continue;

                throw new DKSaml20FormatException("The DK-SAML 2.0 profile requires that all attribute values are of type \"xs:string\".");
            }
        }

        public void ValidateEncryptedAttribute(EncryptedElement encryptedElement)
        {
            throw new DKSaml20FormatException("The DK-SAML 2.0 profile does not support the EncryptedAttribute element");
        }
    }
}