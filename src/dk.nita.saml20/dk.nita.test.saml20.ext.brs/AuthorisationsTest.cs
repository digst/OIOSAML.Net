using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using dk.nita.saml20.ext.brs;
using dk.nita.saml2.ext.brs.schema;
using dk.nita.saml20.Utils;

namespace dk.nita.test
{
    [TestFixture]
    public class AuthorisationsTest
    {
        [Test]
        public void LoadFromBase64String()
        {
            AuthorisationsParser ap = new AuthorisationsParser();
            ap.Load("PGJyczpBdXRob3Jpc2F0aW9ucyB4bWxuczpicnM9Imh0dHA6Ly93d3cuZW9ncy5kay8yMDA3LzA3 L2JycyI+PGJyczpBdXRob3Jpc2F0aW9uIHJlc291cmNlPSJ1cm46ZGs6Y3ZyOmNWUm51bWJlcklk ZW50aWZpZXI6Mjk1Mzc2ODIiPjxicnM6UHJpdmlsZWdlPlNhZmV3aGVyZVRlc3RQcml2aWxlZ2ll PC9icnM6UHJpdmlsZWdlPjwvYnJzOkF1dGhvcmlzYXRpb24+PC9icnM6QXV0aG9yaXNhdGlvbnM+");

            Assert.That(ap.HasPrivilege(AuthorisationsParser.PrivilegeFor.CvrNumber, "29537682", "SafewhereTestPrivilegie"), "User does not have expected privilege");
        }

        [Test]
        public void LoadFromStronglyTypedObject()
        {
            string privilege = "TestPriv";
            string cvrNumber = "29537682";
            AuthorisationsParser ap = new AuthorisationsParser();
            AuthorisationsType at = new AuthorisationsType();

            PrivilegeType priv = new PrivilegeType();
            priv.Value = privilege;

            AuthorisationType auth = new AuthorisationType();
            auth.resource = "urn:dk:cvr:cVRnumberIdentifier:" + cvrNumber;
            auth.Privilege.Add(priv);
            at.Authorisations.Add(auth);

            ap.Load(at);

            Assert.That(ap.HasPrivilege(AuthorisationsParser.PrivilegeFor.CvrNumber, cvrNumber, privilege), "User does not have expected privilege");

        }

        [Test]
        public void HasPrivilege1()
        {
            string privilege = "TestPriv";
            string cvrNumber = "29537682";
            AuthorisationsParser ap = new AuthorisationsParser();
            AuthorisationsType at = new AuthorisationsType();

            PrivilegeType priv = new PrivilegeType();
            priv.Value = privilege;

            AuthorisationType auth = new AuthorisationType();
            auth.resource = "urn:dk:cvr:cVRnumberIdentifier:" + cvrNumber;
            auth.Privilege.Add(priv);
            at.Authorisations.Add(auth);

            ap.Load(at);

            Assert.IsFalse(ap.HasPrivilege(AuthorisationsParser.PrivilegeFor.CvrNumber, "asdf", privilege), "User unexpectedly has privilege");
        }

        [Test]
        public void HasPrivilege2()
        {
            string privilege = "TestPriv";
            string cvrNumber = "29537682";
            AuthorisationsParser ap = new AuthorisationsParser();
            AuthorisationsType at = new AuthorisationsType();

            PrivilegeType priv = new PrivilegeType();
            priv.Value = privilege;

            AuthorisationType auth = new AuthorisationType();
            auth.resource = "urn:dk:cvr:cVRnumberIdentifier:" + cvrNumber;
            auth.Privilege.Add(priv);
            at.Authorisations.Add(auth);

            ap.Load(at);

            Assert.IsFalse(ap.HasPrivilege(AuthorisationsParser.PrivilegeFor.ProductionUnit, cvrNumber, privilege), "User unexpectedly has privilege");
        }

        [Test]
        public void HasPrivilege3()
        {
            string privilege = "TestPriv";
            string productionUnit = "6029537682";
            AuthorisationsParser ap = new AuthorisationsParser();
            AuthorisationsType at = new AuthorisationsType();

            PrivilegeType priv = new PrivilegeType();
            priv.Value = privilege;

            AuthorisationType auth = new AuthorisationType();
            auth.resource = "urn:dk:cvr:productionUnitIdentifier:" + productionUnit;
            auth.Privilege.Add(priv);
            at.Authorisations.Add(auth);

            ap.Load(at);

            Assert.That(ap.HasPrivilege(AuthorisationsParser.PrivilegeFor.ProductionUnit, productionUnit, privilege), "User unexpectedly does not have privilege for production unit");
        }

        [Test]
        public void HasPrivilege4()
        {
            string privilege = "TestPriv";
            string productionUnit = "6029537682";
            AuthorisationsParser ap = new AuthorisationsParser();
            AuthorisationsType at = new AuthorisationsType();

            PrivilegeType priv = new PrivilegeType();
            priv.Value = privilege;

            AuthorisationType auth = new AuthorisationType();
            auth.resource = "urn:dk:cvr:productionUnitIdentifier:" + productionUnit;
            auth.Privilege.Add(priv);
            at.Authorisations.Add(auth);

            ap.Load(at);

            Assert.IsFalse(ap.HasPrivilege(AuthorisationsParser.PrivilegeFor.CvrNumber, productionUnit, privilege), "User unexpectedly has privilege for cvr number");
        }

        [Test]
        public void HasPrivilege5()
        {
            string privilege = "SomePrivilege";
            string productionUnit = "6029537682";
            AuthorisationsParser ap = new AuthorisationsParser();
            AuthorisationsType at = new AuthorisationsType();

            PrivilegeType priv = new PrivilegeType();
            priv.Value = privilege;

            AuthorisationType auth = new AuthorisationType();
            auth.resource = "urn:dk:cvr:productionUnitIdentifier:" + productionUnit;
            auth.Privilege.Add(priv);
            at.Authorisations.Add(auth);

            string xml = Serialization.SerializeToXmlString(at);

            ap.Load(Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)));

            Assert.That(ap.HasPrivilege(AuthorisationsParser.PrivilegeFor.ProductionUnit, productionUnit, privilege), "User unexpectedly does not have privilege for production unit");
        }


        [Test]
        [ExpectedException(typeof(Saml20BRSException))]
        public void NotLoaded()
        {
            AuthorisationsParser ap = new AuthorisationsParser();
            ap.HasPrivilege(AuthorisationsParser.PrivilegeFor.CvrNumber, "", "");
        }

        [Test]
        [ExpectedException(typeof(Saml20BRSException))]
        public void LoadException()
        {
            AuthorisationsParser ap = new AuthorisationsParser();
            ap.Load("InvalidValue");
        }

        [Test]
        public void AuthorisationsEmpty()
        {
            AuthorisationsType at = new AuthorisationsType();
            AuthorisationsParser ap = new AuthorisationsParser();

            ap.Load(at);

            bool result = ap.HasPrivilege(AuthorisationsParser.PrivilegeFor.CvrNumber, "", "");

            Assert.IsFalse(result, "Has privilege unexpectedly returned true");
        }

        
    }
}
