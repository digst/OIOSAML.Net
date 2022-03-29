using dk.nita.saml20.AuthnRequestAppender;
using NUnit.Framework;

namespace dk.nita.test.Saml20.AuthnRequestAppender
{
    [TestFixture]
    public class AuthnRequestAppenderFactoryTest
    {

        [Test]
        public void CanGetAppenderFromConfig()
        {
            //Arrange
            
            //This test assumes that app.config Federation element contains the following element
            //<AuthnRequestAppender type="dk.nita.test.Saml20.AuthnRequestAppender.AuthnRequestAppenderSample, dk.nita.test.Saml20"/>

            //Act
            var appender = AuthnRequestAppenderFactory.GetAppender();
            //Assert
            Assert.NotNull(appender);
            Assert.IsInstanceOf<AuthnRequestAppenderSample>(appender);
        }
    }
}