using dk.nita.saml20.Schema.BasicPrivilegeProfile;
using dk.nita.saml20.Utils;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Schema.BasicPrivilegeProfile
{
    [TestFixture]
    public class PrivilegeListTypeTest
    {
        [Test]
        public void CanDeserializeXml()
        {
            const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<bpp:PrivilegeList xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:bpp=\"http://digst.dk/oiosaml/basic_privilege_profile\">\n\t<PrivilegeGroup Scope=\"urn:dk:gov:saml:cvrNumberIdentifier:93825592\">\n\t\t<Privilege>urn:dk:nemrefusion:privilegium1</Privilege>\n\t</PrivilegeGroup>\n</bpp:PrivilegeList>";
            var privilegeList = Serialization.DeserializeFromXmlString<PrivilegeListType>(xml);
            
            Assert.NotNull(privilegeList);
            Assert.AreEqual(1, privilegeList.PrivilegeGroups.Length);

            var privilegeGroup = privilegeList.PrivilegeGroups[0];
            Assert.AreEqual("urn:dk:gov:saml:cvrNumberIdentifier:93825592", privilegeGroup.Scope);
            Assert.IsNull(privilegeGroup.Constraint);
            Assert.AreEqual(1, privilegeGroup.Privilege.Length);

            var privilege = privilegeGroup.Privilege[0];
            Assert.AreEqual("urn:dk:nemrefusion:privilegium1", privilege);
        }
    }
}