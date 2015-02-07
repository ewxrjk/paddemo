using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace paddemo
{
    class Program
    {

        static void Main(string[] args)
        {
            // Create a key
            var k = Aes.Create();

            // Display properties
            Console.WriteLine("Cipher mode:  {0}", k.Mode);
            Console.WriteLine("Padding mode: {0}", k.Padding);

            EncryptSimple(k);

            // Probably running from inside VS so give user a chance to see output
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey(); 
        }

        /// <summary>
        /// Encrypt a value and then decrypt it.
        /// </summary>
        /// <param name="k">Key to encrypt with</param>
        static void EncryptSimple(SymmetricAlgorithm k)
        {
            var plaintext = "If the current Key property is null, the GenerateKey method is called to create a new random Key. If the current IV property is null, the GenerateIV method is called to create a new random IV.";
            var plaintext_bytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
            var e = k.CreateEncryptor();
            var iv = k.IV;
            var ciphertext_bytes = e.TransformFinalBlock(plaintext_bytes, 0, plaintext_bytes.Length);
            Console.WriteLine("Original plaintext: {0}", plaintext);
            Console.WriteLine("IV:                 {0}", ToHex(iv));
            Console.WriteLine("Ciphertext:         {0}", ToHex(ciphertext_bytes));
            var d = k.CreateDecryptor();
            var decrypted_bytes = d.TransformFinalBlock(ciphertext_bytes, 0, ciphertext_bytes.Length);
            var decrypted = System.Text.Encoding.UTF8.GetString(decrypted_bytes);
            Console.WriteLine("Decrypted:          {0}", decrypted);
            Console.WriteLine("");
            Console.WriteLine("Attempt to decrypt modified ciphertext...");
            ciphertext_bytes[ciphertext_bytes.Length - 1]--;
            d = k.CreateDecryptor();
            try
            {
                decrypted_bytes = d.TransformFinalBlock(ciphertext_bytes, 0, ciphertext_bytes.Length);
                decrypted = System.Text.Encoding.UTF8.GetString(decrypted_bytes);
                Console.WriteLine("Decrypted:          {0}", decrypted);
            }
            catch (Exception error)
            {
                Console.WriteLine("Error:              {0}", error.Message);
            }
        }

        /// <summary>
        /// Convert a byte array to hex
        /// </summary>
        /// <param name="bytes">Value to convert</param>
        /// <returns>Hex dump of <paramref name="bytes"/></returns>
        static string ToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }

    }
}
