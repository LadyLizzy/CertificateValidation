using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharedUtilities;

namespace Client
{
    class Client
    {
        /// <summary>
        /// Creating a client and trying to connect and authenticate it to the server
        /// </summary>
        static void Main()
        {
            var client = new TcpClient(Utilities.ServerIp, Utilities.Port);

            using (var sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate))
            {
                try
                {
                    AuthenticateAsClient(sslStream);

                    if (sslStream.IsAuthenticated && sslStream.IsEncrypted && sslStream.IsSigned)
                        CommunicateWithServer(sslStream);
                }
                catch (AuthenticationException e)
                {
                    Utilities.HandleAuthenticationException(e);
                }

                Console.ReadLine();
            }
        }

        /// <summary>
        /// Gets client certicates collection from mmc and prompts user to choose one to authenticate with.
        /// Since we are using self signed certificates we won't be checking the revocation list
        /// </summary>
        private static void AuthenticateAsClient(SslStream sslStream)
        {
            var certificates = GetClientCertificates();
            var clientCertificates = X509Certificate2UI.SelectFromCollection(certificates, "Select Client Certificate", null, X509SelectionFlag.SingleSelection);
            
            sslStream.AuthenticateAsClient(Utilities.ServerName, clientCertificates, SslProtocols.Tls12, false);
        }

        /// <summary>
        /// Gets the client certificates in the specified store location
        /// </summary>
        private static X509Certificate2Collection GetClientCertificates()
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            var clientCertificates = store.Certificates;
            store.Close();

            return clientCertificates;
        }

        /// <summary>
        /// Callback of the Client.RemoteCertificateValidationDelegate where we check for errors and decide to accept or reject the server certificate.
        /// </summary>
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None) return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            return false;
        }

        /// <summary>
        /// To check that the connection works we try some write and read communication with the server
        /// </summary>
        private static void CommunicateWithServer(SslStream sslStream)
        {
            Console.WriteLine("Server is authenticated. Name: " + Utilities.ServerName + " IP:" + Utilities.ServerIp);

            string serverMessage = Utilities.ReadMessage(sslStream);
            Console.WriteLine("Server says: " + serverMessage);

            Console.WriteLine("Sending hello message to server..");
            sslStream.Write(Encoding.ASCII.GetBytes("Hello from the client!"));
        }
    }
}