using dk.nita.saml20.Utils;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class IdpSelectionUtilTest
    {
        [Test]
        [TestCase("spID", true, true, "Android", ExpectedResult = @"/demo/login.ashx?cidp=spID&forceAuthn=True&isPassive=True&levelOfAssurance=Substantial&profile=Person&appSwitchPlatform=Android")]
        [TestCase("spID", false, true, "Android", ExpectedResult = @"/demo/login.ashx?cidp=spID&forceAuthn=False&isPassive=True&levelOfAssurance=Substantial&profile=Person&appSwitchPlatform=Android")]
        [TestCase("spID", false, false, "Android", ExpectedResult = @"/demo/login.ashx?cidp=spID&forceAuthn=False&isPassive=False&levelOfAssurance=Substantial&profile=Person&appSwitchPlatform=Android")]
        [TestCase("spID", true, false, "Android", ExpectedResult = @"/demo/login.ashx?cidp=spID&forceAuthn=True&isPassive=False&levelOfAssurance=Substantial&profile=Person&appSwitchPlatform=Android")]
        [TestCase("spID", true, true, "iOS", ExpectedResult = @"/demo/login.ashx?cidp=spID&forceAuthn=True&isPassive=True&levelOfAssurance=Substantial&profile=Person&appSwitchPlatform=iOS")]
        [TestCase("spID", false, true, "Android", ExpectedResult = @"/demo/login.ashx?cidp=spID&forceAuthn=False&isPassive=True&levelOfAssurance=Substantial&profile=Person&appSwitchPlatform=Android")]
        [TestCase("spID", false, false, "Android", ExpectedResult = @"/demo/login.ashx?cidp=spID&forceAuthn=False&isPassive=False&levelOfAssurance=Substantial&profile=Person&appSwitchPlatform=Android")]
        public string GetIdpLoginUrlShallReturnCorrectUrlForAppSwitch(string spId, bool forceAuth, bool isPassive, string appSwitchPlatform)
        {
            return IDPSelectionUtil.GetIDPLoginUrl(spId, forceAuth, isPassive,"Substantial", "Person", appSwitchPlatform);
        }
    }
}