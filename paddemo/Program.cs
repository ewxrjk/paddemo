using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace paddemo {
    /// <summary>
    /// Container for a ciphertext
    /// </summary>
    class CipherText {
        /// <summary>
        /// IV
        /// </summary>
        public byte[] iv = null;

        /// <summary>
        /// Encrypted bytes
        /// </summary>
        public byte[] encrypted = null;

        /// <summary>
        /// Create an empty ciphertext
        /// </summary>
        /// <param name="iv"></param>
        /// <param name="encrypted"></param>
        public CipherText() {
        }

        /// <summary>
        /// Create a ciphertext by encrypting a plaintext under a supplied key
        /// </summary>
        /// <param name="k">Encryption key</param>
        /// <param name="plaintext">Plaintext to encrypt</param>
        public CipherText(SymmetricAlgorithm k, byte[] plaintext) {
            var encryptor = k.CreateEncryptor(); // creates a fresh IV
            this.iv = k.IV;
            this.encrypted = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        /// <summary>
        /// Test whether the padding of the plaintext is valid, without revealing the plaintext
        /// </summary>
        /// <param name="k">Encryption key</param>
        /// <returns>true if the padding is valid, false otherwise</returns>
        public bool PaddingOracle(SymmetricAlgorithm k) {
            k.IV = iv;
            var decryptor = k.CreateDecryptor();
            try {
                var decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
                // If decryption succeeded then the padding was correct
                return true;
            }
            catch (System.Security.Cryptography.CryptographicException) {
                // If the padding wasn't correct then the decryptor raises an exception
                return false;
            }
        }
    }

    /// <summary>
    /// Implementation of Vaudenay's padding oracle attack
    /// </summary>
    /// <remarks>
    /// See https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf for
    /// a description.  The naming used here follows the paper as far as possible,
    /// but indexing starts at 0 rather than 1.  Words size is assumed to be 8 bits
    /// throughout (i.e. a "word" here is a byte).
    /// </remarks>
    class Vaudenay2001 {
        /// <summary>
        /// Construct an instance of the attack using a particular padding oracle
        /// </summary>
        /// <param name="O">Padding oracle to use</param>
        /// <param name="b">Block size of the underlying cipher in bytes</param>
        public Vaudenay2001(Predicate<byte[]> O, int b) {
            this.O = O;
            this.b = b;
        }

        /// <summary>
        /// The padding oracle
        /// </summary>
        private Predicate<byte[]> O;

        /// <summary>
        /// The block size in bytes
        /// </summary>
        private int b;

        /// <summary>
        /// RNG to use
        /// </summary>
        static private RandomNumberGenerator RNG = new RNGCryptoServiceProvider();

        /// <summary>
        /// Recover (at least) the last word of plaintext from an encrypted block
        /// </summary>
        /// <param name="y">A single encrypted block</param>
        /// <returns>The last word of <paramref name="y"/> when decrypted via the padding oracle</returns>
        /// <remarks>s3.1 of the paper</remarks>
        private byte[] LastWordOracle(byte[] y) {
            // ry will be what the paper calls r|y
            byte[] ry = new byte[2 * b];
            // 1. pick a few random words r1, . . . , rb and take i = 0
            // r[0...b-1] will be r1...rb
            byte[] r = new byte[b];
            RNG.GetBytes(r);
            byte i = 0;
            while (true) {
                // 2. pick r = r1 . . . r(b−1)(rb ⊕ i)
                Array.Copy(r, 0, ry, 0, b);
                ry[b - 1] ^= i;
                // 3. if O(r|y) = 0 then increment i and go back to the previous step
                Array.Copy(y, 0, ry, b, b);
                if (O(ry) == true)
                    break;
                ++i;
            }
            // 4. replace rb by rb ⊕ i
            r[b - 1] ^= i;
            // 5. for n = b down to 2 do
            for (int n = b; n >= 2; --n) {
                //  (a) take r = r1 . . . rb−n(r(b−n+1) ⊕ 1)r(b−n+2) . . . rb
                Array.Copy(r, 0, ry, 0, b);
                ry[b - n] ^= 1;
                //  (b) if O(r|y) = 0 then stop and output (r(b−n+1) ⊕ n). . .(rb ⊕ n)
                Array.Copy(y, 0, ry, b, b);
                if (O(ry) == false) {
                    byte[] results = new byte[n];
                    for (int j = 0; j < n; ++j)
                        results[j] = (byte)(r[b - n + j] ^ n);
                    return results;
                }
            }
            // 6. output rb ⊕ 1
            int result = r[b - 1] ^ 1;
            return new byte[] { (byte)result };
        }

        /// <summary>
        /// Recover the plaintext of an encrypted block
        /// </summary>
        /// <param name="y">A single encrypted block</param>
        /// <returns>The plaintext corresponding to <paramref name="y"/></returns>
        /// <param name="prev">Array containing previous block or IV</param>
        /// <param name="offset">Offset of previous block or IV in <paramref name="prev"/></param>
        private byte[] BlockDecryptionOracle(byte[] y, byte[] prev, int offset) {
            // ry will be what the paper calls r|y
            byte[] ry = new byte[2 * b];
            // "Assuming that we already managed to get aj . . . ab for some j ≤ b ..."
            // Note: rather than keeping a[0...b-1] around all the time, this
            // implementation just keeps what it knows and gradually extends the
            // array from the front (in step 5).
            byte[] a = LastWordOracle(y);
            Report(a, prev, offset);
            // r[0...b-1] will be r1...rb
            byte[] r = new byte[b];
            while (a.Length < b) {
                // 2. pick r1, . . . , rj−1 at random and take i = 0
                RNG.GetBytes(r);
                byte i = 0;
                // 1. take rk = ak ⊕ (b − j + 2) for k = j, . . . , b
                for (int k = 1; k <= a.Length; ++k) {
                    r[b - k] = (byte)(a[a.Length - k] ^ (a.Length + 1));
                }
                while (true) {
                    // 3. take r = r1 . . . r(j−2)(r(j−1) ⊕ i)rj . . . rb
                    Array.Copy(r, 0, ry, 0, b);
                    ry[b - a.Length - 1] ^= i;
                    // 4. if O(r|y) = 0 then increment i and go back to the previous step
                    Array.Copy(y, 0, ry, b, b);
                    if (O(ry))
                        break;
                    ++i;
                }
                // 5. output r(j−1) ⊕ i ⊕ (b − j + 2)
                byte[] anew = new byte[a.Length + 1];
                anew[0] = (byte)(r[b - a.Length - 1] ^ i ^ (a.Length + 1));
                Array.Copy(a, 0, anew, 1, a.Length);
                a = anew;
                Report(a, prev, offset);
            }
            return a;
        }

        /// <summary>
        /// Recover the entire plaintext of an encrypted sequence of bytes
        /// </summary>
        /// <param name="iv">IVs</param>
        /// <param name="ys">One or more encrypted blocks</param>
        /// <returns>The plaintext corresponding to <paramref name="ys"/></returns>
        public byte[] Decrypt(byte[] iv, byte[] ys) {
            byte[] y = new byte[b];
            byte[] p = new byte[ys.Length];
            for (int i = 0; i < ys.Length; i += b) {
                Array.Copy(ys, i, y, 0, b);
                var d = BlockDecryptionOracle(y,
                                              i == 0 ? iv : ys,
                                              i == 0 ? i : i - b);
                for (int n = 0; n < b; ++n)
                    p[i + n] = (byte)(d[n] ^ (i == 0 ? iv[n] : ys[i + n - b]));
            }
            // TODO strip final padding
            return p;
        }

        /// <summary>
        /// Report an intermediate value
        /// </summary>
        /// <param name="a">Intermediate byte array</param>
        /// <param name="prev">Array containing previous block or IV</param>
        /// <param name="offset">Offset of previous block or IV in <paramref name="prev"/></param>
        private void Report(byte[] a, byte[] prev, int offset) {
            byte[] mixed = new byte[b];
            for (int i = 0; i < a.Length; ++i)
                mixed[b - a.Length + i] = (byte)(a[i] ^ prev[offset + b - a.Length + i]);
            Console.WriteLine("{0}{1} ^ {2} = {3} = {4}",
               new string('?', 2 * (b - a.Length)),
               Program.ToHex(a),
               Program.ToHex(prev, offset, b),
               Program.ToHex(mixed),
               System.Text.Encoding.UTF8.GetString(mixed));
        }
    };

    class Program {

        static void Main(string[] args) {
            var k = DES.Create(); // or Aes.Create();
            Console.WriteLine("Cipher mode:  {0}", k.Mode);
            Console.WriteLine("Padding mode: {0}", k.Padding);
            EncryptSimple(k);
            Wait();
            UseAttack(k);
            Wait();
        }

        /// <summary>
        /// Encrypt a value and demonstrate that the padding oracle reports bogus ciphertexts.
        /// </summary>
        /// <param name="k">Key to encrypt with</param>
        static void EncryptSimple(SymmetricAlgorithm k) {
            var plaintext = "If the current Key property is null, the GenerateKey method is called to create a new random Key. ";
            var plaintext_bytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
            var ciphertext = new CipherText(k, plaintext_bytes);
            Console.WriteLine("Original plaintext: {0}", plaintext);
            Console.WriteLine("IV:                 {0}", ToHex(ciphertext.iv));
            Console.WriteLine("Ciphertext:         {0}", ToHex(ciphertext.encrypted));
            Console.WriteLine("Padding oracle:     {0}", ciphertext.PaddingOracle(k));
            Console.WriteLine("");
            Console.WriteLine("Changing last byte of ciphertext...");
            ciphertext.encrypted[ciphertext.encrypted.Length - 1]--;
            Console.WriteLine("Ciphertext:         {0}", ToHex(ciphertext.encrypted));
            Console.WriteLine("Padding oracle:     {0}", ciphertext.PaddingOracle(k));
        }

        /// <summary>
        /// Encrypt a value and recover it use the attack
        /// </summary>
        /// <param name="k">Key to encrypt with</param>
        static void UseAttack(SymmetricAlgorithm k) {
            var plaintext = "If the current Key property is null, the GenerateKey method is called to create a new random Key. ";
            var plaintext_bytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
            var ciphertext = new CipherText(k, plaintext_bytes);
            Console.WriteLine("Plaintext bytes:    {0}", ToHex(plaintext_bytes));
            Console.WriteLine("Ciphertext:         {0}", ToHex(ciphertext.encrypted)); // TODO remove me
            var attack = new Vaudenay2001((byte[] c) => (new CipherText() { iv = k.IV, encrypted = c }).PaddingOracle(k),
                                          k.BlockSize / 8);
            var decrypted = attack.Decrypt(k.IV, ciphertext.encrypted);
            Console.WriteLine("Decrypted using attack: {0}", System.Text.Encoding.UTF8.GetString(decrypted));
        }

        /// <summary>
        /// Convert a byte array to hex
        /// </summary>
        /// <param name="bytes">Value to convert</param>
        /// <param name="offset">Starting position in <paramref name="bytes"/></param>
        /// <param name="len">Number of bytes to convert</param>
        /// <returns>Hex dump of <paramref name="bytes"/></returns>
        static public string ToHex(byte[] bytes, int offset = 0, int len = int.MaxValue) {
            var writer = new StringWriter();
            offset = Math.Min(offset, bytes.Length);
            len = Math.Min(len, bytes.Length - offset);
            for (int i = 0; i < len; ++i)
                writer.Write("{0:x2}", bytes[offset + i]);
            return writer.ToString();
        }

        static void Wait() {
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
            Console.Clear();
        }
    }
}
