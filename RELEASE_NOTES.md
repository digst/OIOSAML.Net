# OIO SAML 3

## 3.0.4
- NLRFIM-169: Support AppSwitch extension on AuthnRequest in Java OIO SAML 3

## 3.0.2
- NLRFIM-157: Added configurable IAuthnRequestAppender to allow additional modifications by the user of the package just before the AuthnRequest is signed and transferred.

## 3.0.1
- NLRFIM-99: Fixing use of regular expression match for iOS user agent in BrowserSupportUtil
- NLRFIM-111: Updated documentation for configuration of signing certificates in configuration file
- NLRFIM-119: Minor fixes
  - Add EncryptionMethod URLs for RSA-OAEP-MGF1P and AES256-CBC as default in metadata
  - Don't add NSIS LoA Low in IdentityProviderDemo when old AssuranceLevel is used to Assertion
  - Serialize comparison attribute correctly in AuthnRequest
- NLRFIM-117: Update text used WebSiteDemo when request a professional identity
- NLRFIM-118: Update XML namespace for OIO BPP to http://digst.dk/oiosaml/basic_privilege_profile cf. profile version 1.2
- NLRFIM-127: Protect against cross-site scripting for NSIS LoA and profile request parameters in Saml20SignonHandler.cs

## 3.0.0
First official release OIO SAML 3.

# OIO SAML 2

## 2.0.6
Stable OIO SAML 2 reference implementation.
