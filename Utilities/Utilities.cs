using System;
using System.IO;
using System.Security.Authentication;
using System.Text;

namespace SharedUtilities
{
    public class Utilities
    {
        public const string ServerThumbprint = "c20797270bef02bd66b30224ec640c037663c305"; //thumbprint of the ServerCert.pfx
        public const string ServerIp = "127.0.0.1"; //localhost
        public const string ServerName = "yourdomain.com"; //the CN of the server cert
        public const int Port = 1300;

        public static void HandleAuthenticationException(AuthenticationException e)
        {
            Console.WriteLine("An error occoured: {0}", e.Message);

            if (e.InnerException != null)
                Console.WriteLine("Inner exception: {0}", e.InnerException.Message);

            Console.WriteLine("Authentication failed - closing the connection.");
        }

        public static string ReadMessage(Stream sslStream)
        {
            var buffer = new byte[2048];
            var messageData = new StringBuilder();
            int bytesReadCount = sslStream.Read(buffer, 0, buffer.Length);

            Decoder decoder = Encoding.ASCII.GetDecoder();
            var chars = new char[decoder.GetCharCount(buffer, 0, bytesReadCount)];
            decoder.GetChars(buffer, 0, bytesReadCount, chars, 0);
            messageData.Append(chars);

            return messageData.ToString();
        }
    }
}
