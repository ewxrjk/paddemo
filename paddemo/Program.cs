using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace paddemo
{
    /// <summary>
    /// Container for a ciphertext
    /// </summary>
    class CipherText
    {
        /// <summary>
        /// IV
        /// </summary>
        public byte[] iv;

        /// <summary>
        /// Encrypted bytes
        /// </summary>
        public byte[] encrypted;

        /// <summary>
        /// Create a ciphertext by encrypting a plaintext under a supplied key
        /// </summary>
        /// <param name="k">Encryption key</param>
        /// <param name="plaintext">Plaintext to encrypt</param>
        public CipherText(SymmetricAlgorithm k, byte[] plaintext)
        {
            var encryptor = k.CreateEncryptor(); // creates a fresh IV
            iv = k.IV;
            encrypted = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

    }

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
            var ciphertext = new CipherText(k, plaintext_bytes);
            Console.WriteLine("Original plaintext: {0}", plaintext);
            Console.WriteLine("IV:                 {0}", ToHex(ciphertext.iv));
            Console.WriteLine("Ciphertext:         {0}", ToHex(ciphertext.encrypted));
            var d = k.CreateDecryptor();
            var decrypted_bytes = d.TransformFinalBlock(ciphertext.encrypted, 0, ciphertext.encrypted.Length);
            var decrypted = System.Text.Encoding.UTF8.GetString(decrypted_bytes);
            Console.WriteLine("Decrypted:          {0}", decrypted);
            Console.WriteLine("");
            Console.WriteLine("Attempt to decrypt modified ciphertext...");
            ciphertext.encrypted[ciphertext.encrypted.Length - 1]--;
            d = k.CreateDecryptor();
            try
            {
                decrypted_bytes = d.TransformFinalBlock(ciphertext.encrypted, 0, ciphertext.encrypted.Length);
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
