using System;
using System.IO;
using System.Security.Cryptography;

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
        public Vaudenay2001(Predicate<byte[]> Oracle, int b) {
            this.Oracle = Oracle;
            this.b = b;
        }

        /// <summary>
        /// The padding oracle
        /// </summary>
        private Predicate<byte[]> Oracle;

        /// <summary>
        /// The block size in bytes
        /// </summary>
        private int b;

        /// <summary>
        /// RNG to use
        /// </summary>
        static private RandomNumberGenerator RNG = new RNGCryptoServiceProvider();

        /// <summary>
        /// Count of queries to the oracle
        /// </summary>
        private int queries = 0;

        /// <summary>
        /// Query the oracle, counting the number of queries
        /// </summary>
        /// <param name="b">Ciphertext</param>
        /// <returns>true if <paramref name="b"/> decrypts to a well-formed plaintext, else false</returns>
        private bool O(byte[] b) {
            ++queries;
            return Oracle(b);
        }

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
            /* What O(r|y) actually does, with D() representing a raw 1-block decryption:
             *     (i) compute P1 = D(r) ⊕ IV
             *    (ii) throw P1 away
             *   (iii) compute P2 = D(y) ⊕ r
             *    (iv) return true if P2 is correctly padded for a final block
             *     (v) return false if it is not
             *
             * By now the attacker has found a value of r such that r ⊕ D(y) ends
             * with valid padding.  In other words one of the following possibilities:
             *      D(y) ⊕ r = ??????????????01
             *   or D(y) ⊕ r = ????????????0202
             *   or D(y) ⊕ r = ??????????030303
             * etc.  (Assuming for presentational purposes that b=8.)
             *
             * The attacker doesn't know which of these is true so their next task
             * is to distinguish between them somehow. The strategy used is to
             * discover which byte has to be corrupted to break the padding.
             *
             * To see how this works suppose first that the situation is:
             *      D(y) ⊕ r = 0808080808080808
             * The attacker modifies the first byte of r:
             *      D(y) ⊕ r ⊕ 0100000000000000 = 0908080808080808
             * The oracle will reject this since P2 = 0908080808080808 isn't correctly padded.
             * The attacker would therefore conclude that D(y) = 0808080808080808 ⊕ r.
             *
             * Suppose second that the situation is:
             *      D(y) ⊕ r = 0507070707070707
             * The attacker first tries modifying the first byte of r:
             *      D(y) ⊕ r ⊕ 0100000000000000 = 0407070707070707
             * This is still correctly padded so the oracle will accept it.  The
             * attacker therefore moves on to the second byte of r:
             *      D(y) ⊕ r ⊕ 0001000000000000 = 0506070707070707
             * Now the oracle rejects this since P2 = 0506070707070707 isn't correctly padded.
             * The attacker would therefore conclude that D(y) = ??07070707070707 ⊕ r.
             *
             * This exercise is repeated for each byte in turn.
             * 
             * The choice of ⊕ 1 as the modification of the target byte is completely
             * arbitrary - the attacker could add 1, or invert it, or add n, anything
             * that changes it will do.
             */
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
            /* The attacker has concluded that the padding at the end of r ⊕ D(y)
             * is a single byte of value 1.  They can therefore recover the last
             * byte of D(y):
             *     D(y) ⊕ r = ??????????????01
             *  =>     D(y) = ??????????????01 ⊕ r
             */
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
        /// <remarks>s3.2 of the paper</remarks>
        private byte[] BlockDecryptionOracle(byte[] y, byte[] prev, int offset) {
            // ry will be what the paper calls r|y
            byte[] ry = new byte[2 * b];
            // "Assuming that we already managed to get aj . . . ab for some j ≤ b ..."
            /* Note: rather than keeping a[0...b-1] around all the time, this
             * implementation just keeps what it knows and gradually extends the
             * array from the front (in step 5).
             */
            byte[] a = LastWordOracle(y);
            Report(a, prev, offset);
            // r[0...b-1] will be r1...rb
            byte[] r = new byte[b];
            while (a.Length < b) {
                /* As above, assume b=8 for presentational purposes.
                 * 
                 * As the loop repeats the situation looks like this:
                 *     a = ????????????u2x1
                 *     a = ??????????u3x2x1
                 *     a = ????????u4x3x2x1
                 *     a = ??????u5x4x3x2x1
                 *     etc.
                 * where:
                 *    xN represents the known part of the result
                 *    uN represents the (currently unknown) next byte to recover.
                 *    
                 * In the explanation below, the example values will correspond
                 * to the half way mark:
                 *     a = ??????u5x4x3x2x1
                 */
                // 2. pick r1, . . . , rj−1 at random and take i = 0
                RNG.GetBytes(r);
                byte i = 0;
                // 1. take rk = ak ⊕ (b − j + 2) for k = j, . . . , b
                /* b-j+2 is one more than the length of the known part.
                 * So this yields something like:
                 *    r = 00000000x4x3x2x1 ⊕ ????????05050505
                 */
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
                /* The attack has tried inserting different bytes zz just before the known
                 * part of a and eventually discovered:
                 *     r = 00000000x4x3x2x1 ⊕ ??????zz05050505
                 * ...such that O(r|y) is satisfied.  Recall that this means that
                 * D(y) ⊕ r is correctly padded - so:
                 *     D(y) ⊕ 00000000x4x3x2x1 ⊕ ??????zz05050505 = ??????????????01
                 *                                          or     = ????????????0202
                 *                                          or     = ??????????030303
                 *                                          etc.
                 * But the attacker also knows the trailing bytes of D(y):
                 *     D(y) = a = ??????u5x4x3x2x1
                 *  => ??????u5x4x3x2x1 ⊕ 00000000x4x3x2x1 ⊕ ??????zz05050505 = ??????????????01
                 *                                                      or     = ????????????0202
                 *                                                      or     = ??????????030303
                 *                                                      etc.
                 * Since the x values appear in the XOR exactly twice they can be eliminated,
                 * and that leaves only one possible adding sequence that fits:
                 *  => ??????u500000000 ⊕ ??????zz05050505 = ??????0505050505
                 *  => u5 ⊕ zz = 05
                 *  => u5 = zz ⊕ 05
                 */
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
        /// <remarks>s3.3 of the paper</remarks>
        public byte[] Decrypt(byte[] iv, byte[] ys) {
            byte[] y = new byte[b];
            byte[] p = new byte[ys.Length];
            int blocks = 0;
            for (int i = 0; i < ys.Length; i += b) {
                Array.Copy(ys, i, y, 0, b);
                var d = BlockDecryptionOracle(y,
                                              i == 0 ? iv : ys,
                                              i == 0 ? i : i - b);
                for (int n = 0; n < b; ++n)
                    p[i + n] = (byte)(d[n] ^ (i == 0 ? iv[n] : ys[i + n - b]));
                ++blocks;
            }
            Console.WriteLine("Mean {0} queries/block", queries / blocks);
            if (p.Length > 0 && p[p.Length - 1] <= b) {
                byte[] result = new byte[p.Length - p[p.Length - 1]];
                Array.Copy(p, 0, result, 0, result.Length);
                return result;
            }
            else
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
            Console.WriteLine("{0,5} {1} ^ {2}{3} = {4} = {5}",
               queries,
               Program.ToHex(prev, offset, b),
               new string('?', 2 * (b - a.Length)),
               Program.ToHex(a),
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
            Console.WriteLine("IV:                 {0}", ToHex(ciphertext.iv));
            Console.WriteLine("Ciphertext:         {0}", ToHex(ciphertext.encrypted));
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
