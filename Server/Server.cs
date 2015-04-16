using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharedUtilities;

namespace Server
{
    internal class Server
    {
        private static TcpListener _listener;

        /// <summary>
        /// Starting the server and waiting for a client to connect on the TCP port. When a client connects we will handle it
        /// </summary>
        private static void Main()
        {
            StartServer();
            TcpClient client = _listener.AcceptTcpClient();
            HandleClient(client);
            StopServer();
        }

        private static void StartServer()
        {
            _listener = new TcpListener(IPAddress.Any, Utilities.Port);
            _listener.Start();
            Console.WriteLine("Server started and is listening for a client on port " + Utilities.Port);
        }

        /// <summary>
        /// When a client connects we open a secure ssl stream to handle the TLS/SSL Handshake and perform mutural authentication
        /// </summary>
        private static void HandleClient(TcpClient client)
        {
            using (var sslStream = new SslStream(client.GetStream(), false, ValidateClientCertificate))
            {
                try
                {
                    AuthenticateAsServer(sslStream);

                    if (sslStream.IsAuthenticated && sslStream.IsEncrypted && sslStream.IsSigned)
                        CommunicateWithClient(sslStream);
                }
                catch (AuthenticationException e)
                {
                    Utilities.HandleAuthenticationException(e);
                }

                Console.ReadLine();
            }
        }

        /// <summary>
        /// Gets the server certificate by it's unique thumbprint and authenticates as the server and sets it to require a client certificate.
        /// Since we are using self signed certificates we won't be checking the revocation list
        /// </summary>
        private static void AuthenticateAsServer(SslStream sslStream)
        {
            var serverCertificate = GetServerCertificateByThumbprint(Utilities.ServerThumbprint);
            sslStream.AuthenticateAsServer(serverCertificate, true, SslProtocols.Tls12, false);
        }

        /// <summary>
        /// Finds the server certificate by provided thumbprint in Local Machine store
        /// </summary>
        private static X509Certificate2 GetServerCertificateByThumbprint(string thumbprint)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            var collection = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true);
            store.Close();

            return collection.Count > 0 ? collection[0] : null;
        }

        /// <summary>
        /// Callback of the Server.RemoteCertificateValidationDelegate where we check for errors and decide to accept or reject the client certificate
        /// </summary>
        public static bool ValidateClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None) return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            return false;
        }

        /// <summary>
        /// To check that it works we try some write and read communication with the client
        /// </summary>
        private static void CommunicateWithClient(SslStream sslStream)
        {
            Console.WriteLine("Client successfully authenticated to the server. You are now connected!");

            Console.WriteLine("Sending message to the client...");
            sslStream.Write(Encoding.ASCII.GetBytes("Hello from server, your client certificate was trusted :-)"));

            string clientMessage = Utilities.ReadMessage(sslStream);
            Console.WriteLine("Client says: " + clientMessage);
        }

        private static void StopServer()
        {
            _listener.Stop();
            Console.WriteLine("\nServer stopped.");
            Console.ReadLine();
        }
    }
}