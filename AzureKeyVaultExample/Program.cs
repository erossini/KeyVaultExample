using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AzureKeyVaultExample
{
    class Program
    {
        const string CLIENTSECRET = "<your client secret>";
        const string CLIENTID = "<your client id>";
        const string BASESECRETURI = "https://yourkeyvaulturl.vault.azure.net/";
        const string SECRETNAME = "ThisIsMyTest";

        static KeyVaultClient kvc = null;

        static void Main(string[] args)
        {
            var _keyVaultClient = new KeyVaultClient(
                async (string authority, string resource, string scope) =>
                {
                    var authContext = new AuthenticationContext(authority);
                    var clientCred = new ClientCredential(CLIENTID, CLIENTSECRET);
                    var result = await authContext.AcquireTokenAsync(resource, clientCred);
                    return result.AccessToken;
                });

            var result = _keyVaultClient.SetSecretAsync(BASESECRETURI, "Password", "This is my password").GetAwaiter().GetResult();

            var pwd = _keyVaultClient.GetSecretAsync(BASESECRETURI, "Password").GetAwaiter().GetResult();
            Console.WriteLine($"The secret passowrd is: {pwd.Value}");

            DoVault();
            Console.ReadLine();
        }

        private static void DoVault()
        {
            kvc = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetToken));

            // write
            WriteKeyVault();
            Console.WriteLine("Press enter after seeing the bundle value show up");
            Console.ReadLine();

            SecretBundle secret = Task.Run(() => kvc.GetSecretAsync(BASESECRETURI +
                @"/secrets/" + SECRETNAME)).ConfigureAwait(false).GetAwaiter().GetResult();
            Console.WriteLine(secret.Tags["Test1"].ToString());
            Console.WriteLine(secret.Tags["Test2"].ToString());
            Console.WriteLine(secret.Tags["CanBeAnything"].ToString());

            Console.ReadLine();

        }

        public static async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(CLIENTID, CLIENTSECRET);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }

        private static async void WriteKeyVault()// string szPFX, string szCER, string szPassword)
        {
            SecretAttributes attribs = new SecretAttributes
            {
                Enabled = true//,
                              //Expires = DateTime.UtcNow.AddYears(2), // if you want to expire the info
                              //NotBefore = DateTime.UtcNow.AddDays(1) // if you want the info to 
                              // start being available later
            };

            IDictionary<string, string> alltags = new Dictionary<string, string>();
            alltags.Add("Test1", "This is a test1 value");
            alltags.Add("Test2", "This is a test2 value");
            alltags.Add("CanBeAnything", "Including a long encrypted string if you choose");
            string TestValue = "searchValue"; // this is what you will use to search for the item later
            string contentType = "SecretInfo"; // whatever you want to categorize it by; you name it

            SecretBundle bundle = await kvc.SetSecretAsync
               (BASESECRETURI, SECRETNAME, TestValue, alltags, contentType, attribs);
            Console.WriteLine("Bundle:" + bundle.Tags["Test1"].ToString());
        }
    }
}
