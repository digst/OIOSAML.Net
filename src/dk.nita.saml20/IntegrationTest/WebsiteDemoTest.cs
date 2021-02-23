using System;
using System.Configuration;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;
using Xunit;

namespace IntegrationTest
{
    public class WebsiteDemoTest
    {
        [Fact]
        public void LoginTest()
        {
            var serviceProviderEndpoint = ConfigurationManager.AppSettings["ServiceProviderEndpoint"];
            var username = ConfigurationManager.AppSettings["IdpUsername"];
            var password = ConfigurationManager.AppSettings["IdpPassword"];
            
            var options = new ChromeOptions();
            options.AddArguments("headless");
            
            var driver = new ChromeDriver(options);
            
            try
            {
                var wait = new WebDriverWait(driver, TimeSpan.FromSeconds(10));
                
                //Navigate to login page
                driver.Navigate().GoToUrl(serviceProviderEndpoint);
                wait.Until(SeleniumExtras.WaitHelpers.ExpectedConditions.ElementIsVisible(By.CssSelector("[href*='/login.aspx/mitidsim']"))).Click();
                
                //Log in
                wait.Until(SeleniumExtras.WaitHelpers.ExpectedConditions.ElementIsVisible(By.Id("ContentPlaceHolder_MitIdSimulatorControl_txtUsername")))
                    .SendKeys(username);
                wait.Until(SeleniumExtras.WaitHelpers.ExpectedConditions.ElementIsVisible(By.Id("ContentPlaceHolder_MitIdSimulatorControl_txtPassword")))
                    .SendKeys(password);
                wait.Until(SeleniumExtras.WaitHelpers.ExpectedConditions.ElementIsVisible(By.Id("ContentPlaceHolder_MitIdSimulatorControl_btnSubmit"))).Click();
                
                //Verify response
                wait.Until(d => d.FindElement(By.XPath("//*[text()='SAML attributes']")));
            }
            finally
            {
                driver.Quit();
            }
        }
    }
}