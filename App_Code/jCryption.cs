/*
 * jCryption.NET is a server side implementation for jCryption v3.0 and ASP.NET
 * written by Jake.Y.Yoshimura
 * MIT license.
 * http://www.opensource.org/licenses/mit-license.php
 * 
 * jCryption client side library is originated by Daniel Griesser:
 * http://www.jcryption.org/
 * 
 * Some SSL related methods are from http://www.jensign.com/opensslkey/opensslkey.cs
 */
using System;
using System.IO;
using System.Collections.Generic;
using System.Collections;
using System.Collections.Specialized;
using System.Text;
using System.Security.Cryptography;
using System.Web;

namespace jCryption
{
    /// <summary>
    /// Utilities from http://www.jensign.com/opensslkey/opensslkey.cs
    /// </summary>
    public static class Utility 
    {
        // -----  Get the binary RSA PRIVATE key, decrypting if necessary ----
        public static byte[] DecodeOpenSSLPrivateKey(String instr)
        {
            const String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----";
            const String pemprivfooter = "-----END RSA PRIVATE KEY-----";
            String pemstr = instr.Trim();
            byte[] binkey;
            if (!pemstr.StartsWith(pemprivheader) || !pemstr.EndsWith(pemprivfooter))
                return null;

            StringBuilder sb = new StringBuilder(pemstr);
            sb.Replace(pemprivheader, "");  //remove headers/footers, if present
            sb.Replace(pemprivfooter, "");

            String pvkstr = sb.ToString().Trim();	//get string after removing leading/trailing whitespace

            try
            {        // if there are no PEM encryption info lines, this is an UNencrypted PEM private key
                binkey = Convert.FromBase64String(pvkstr);
                return binkey;
            }
            catch (System.FormatException)
            {		//if can't b64 decode, it must be an encrypted private key
                //Console.WriteLine("Not an unencrypted OpenSSL PEM private key");  
            }

            StringReader str = new StringReader(pvkstr);

            //-------- read PEM encryption info. lines and extract salt -----
            if (!str.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED"))
                return null;
            String saltline = str.ReadLine();
            if (!saltline.StartsWith("DEK-Info: DES-EDE3-CBC,"))
                return null;
            String saltstr = saltline.Substring(saltline.IndexOf(",") + 1).Trim();
            byte[] salt = new byte[saltstr.Length / 2];
            for (int i = 0; i < salt.Length; i++)
                salt[i] = Convert.ToByte(saltstr.Substring(i * 2, 2), 16);
            if (!(str.ReadLine() == ""))
                return null;

            //------ remaining b64 data is encrypted RSA key ----
            String encryptedstr = str.ReadToEnd();

            try
            {	//should have b64 encrypted RSA key now
                binkey = Convert.FromBase64String(encryptedstr);
            }
            catch (System.FormatException)
            {  // bad b64 data.
                return null;
            }

            // does not support encrypted private key
            throw new NotImplementedException();

#if false
            //------ Get the 3DES 24 byte key using PDK used by OpenSSL ----

            SecureString despswd = GetSecPswd("Enter password to derive 3DES key==>");
            //Console.Write("\nEnter password to derive 3DES key: ");
            //String pswd = Console.ReadLine();
            byte[] deskey = GetOpenSSL3deskey(salt, despswd, 1, 2);    // count=1 (for OpenSSL implementation); 2 iterations to get at least 24 bytes
            if (deskey == null)
                return null;
            //showBytes("3DES key", deskey) ;

            //------ Decrypt the encrypted 3des-encrypted RSA private key ------
            byte[] rsakey = DecryptKey(binkey, deskey, salt);	//OpenSSL uses salt value in PEM header also as 3DES IV
            if (rsakey != null)
                return rsakey;	//we have a decrypted RSA private key
            else
            {
                Console.WriteLine("Failed to decrypt RSA private key; probably wrong password.");
                return null;
            }
#endif
        }

        //--------   Get the binary RSA PUBLIC key   --------
        public static byte[] DecodeOpenSSLPublicKey(String instr)
        {
            const String pempubheader = "-----BEGIN PUBLIC KEY-----";
            const String pempubfooter = "-----END PUBLIC KEY-----";
            String pemstr = instr.Trim();
            byte[] binkey;
            if (!pemstr.StartsWith(pempubheader) || !pemstr.EndsWith(pempubfooter))
                return null;
            StringBuilder sb = new StringBuilder(pemstr);
            sb.Replace(pempubheader, "");  //remove headers/footers, if present
            sb.Replace(pempubfooter, "");

            String pubstr = sb.ToString().Trim();	//get string after removing leading/trailing whitespace

            try
            {
                binkey = Convert.FromBase64String(pubstr);
            }
            catch (System.FormatException)
            {		//if can't b64 decode, data is not valid
                return null;
            }
            return binkey;
        }

        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)		//expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();	// data size in next byte
            else
                if (bt == 0x82)
                {
                    highbyte = binr.ReadByte();	// data size in next 2 bytes
                    lowbyte = binr.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                }
                else
                {
                    count = bt;		// we already have the data size
                }
            while (binr.ReadByte() == 0x00)
            {	//remove high order zeros in data
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);		//last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }

        public static RSAParameters DecodeRSAPrivateKey(byte[] privkey)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
            MemoryStream mem = new MemoryStream(privkey);
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();        //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();       //advance 2 bytes
                else
                    throw new InvalidDataException();//return null;

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102) //version number
                    throw new InvalidDataException(); //return null;
                bt = binr.ReadByte();
                if (bt != 0x00)
                    throw new InvalidDataException(); //return null;


                //------  all private key components are Integer sequences ----
                elems = GetIntegerSize(binr);
                MODULUS = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                E = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                D = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                P = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                Q = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DP = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DQ = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                IQ = binr.ReadBytes(elems);

                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSAParameters RSAparams = new RSAParameters();
                RSAparams.Modulus = MODULUS;
                RSAparams.Exponent = E;
                RSAparams.D = D;
                RSAparams.P = P;
                RSAparams.Q = Q;
                RSAparams.DP = DP;
                RSAparams.DQ = DQ;
                RSAparams.InverseQ = IQ;
                return RSAparams;
            }
            catch (Exception)
            {
                throw new InvalidDataException(); //return null;
            }
            finally
            {
                binr.Close();
            }
        }

        public static String CreateRSAPublicKeyPEM(RSAParameters parameters)
        {
            List<byte> arrBinaryPublicKey = new List<byte>();
            var eList = new List<byte>(parameters.Exponent); CalculateAndAppendLength(eList); eList.Insert(0, 0x02);// INTEGER
            var nList = new List<byte>(parameters.Modulus); CalculateAndAppendLength(nList); nList.Insert(0, 0x02); // INTEGER
            arrBinaryPublicKey.AddRange(nList); arrBinaryPublicKey.AddRange(eList);
            CalculateAndAppendLength(arrBinaryPublicKey); arrBinaryPublicKey.Insert(0, 0x30); // SEQUENCE = 0x30
            arrBinaryPublicKey.Insert(0, 0x00); // ( number of unused bits that exist in the last content byte )
            CalculateAndAppendLength(arrBinaryPublicKey); arrBinaryPublicKey.Insert(0, 0x03); // BIT STRING = 3
            // Oid
            arrBinaryPublicKey.InsertRange(0, new byte[] { 0x30, 0xD, 0x6, 0x9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0xD, 0x1, 0x1, 0x1, 0x5, 0x0  } /* Object ID for RSA The oid for RSA keys is 1.2.840.113549.1.1.1. */);
            CalculateAndAppendLength(arrBinaryPublicKey);
            arrBinaryPublicKey.Insert(0, 0x30); // SEQUENCE
            //End Transformation
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PUBLIC KEY-----")
                .AppendLine(System.Convert.ToBase64String(arrBinaryPublicKey.ToArray(), Base64FormattingOptions.InsertLineBreaks))
                .AppendLine("-----END PUBLIC KEY-----");
            return sb.ToString();
        }

        private static void CalculateAndAppendLength(List<byte> arrBinaryData)
        {
            int nLen;
            nLen = arrBinaryData.Count;
            if (nLen <= byte.MaxValue)
            {
                arrBinaryData.Insert(0, Convert.ToByte(nLen));
                arrBinaryData.Insert(0, 0x81); //This byte means that the length fits in one byte
            }
            else
            {
                arrBinaryData.Insert(0, Convert.ToByte(nLen % (byte.MaxValue + 1)));
                arrBinaryData.Insert(0, Convert.ToByte(nLen / (byte.MaxValue + 1)));
                arrBinaryData.Insert(0, 0x82); //This byte means that the length fits in two byte
            }

        }

        public static void ProcessRequest(HttpContextBase context, RSACryptoServiceProvider cryptoProvider)
        {
            if (context.Request.IsSecureConnection) return;
            var Request = context.Request; var Response = context.Response; var Session = context.Session;
            var conv = new System.Web.Script.Serialization.JavaScriptSerializer();
            if (Request.QueryString["getPublicKey"] != null)
            {
                Response.Cache.SetNoStore();
                var parameter = cryptoProvider.ExportParameters(false);
                Response.Write(conv.Serialize(new { publickey = Utility.CreateRSAPublicKeyPEM(parameter) }));
                Response.ContentType = "application/json";
                Response.End();
            }
            else if (Request.QueryString["handshake"] != null)
            {
                var key = Convert.FromBase64String(Request.Form["key"]);
                var keyDecrypted = cryptoProvider.Decrypt(key, false);
                Session["_key"] = keyDecrypted;
                byte[] saltBytes = new byte[8];
                System.Buffer.BlockCopy(keyDecrypted, 0, saltBytes, 0, 8);
                byte[] toBeEncrypted = new byte[keyDecrypted.Length - 8];
                System.Buffer.BlockCopy(keyDecrypted, 0, toBeEncrypted, 0, keyDecrypted.Length - 8);

                var kd = new OpenSslCompatDeriveBytes(keyDecrypted, saltBytes, "MD5", 1);// new Rfc2898DeriveBytes(keyDecrypted, saltBytes, 1000);
                var aesProvider = new AesCryptoServiceProvider() { KeySize = 256, BlockSize = 128, Mode = CipherMode.CBC };
                var encrypter = aesProvider.CreateEncryptor(kd.GetBytes(aesProvider.KeySize / 8), kd.GetBytes(aesProvider.BlockSize / 8));
                using (var ms = new System.IO.MemoryStream())
                using (var writer = new System.IO.BinaryWriter(ms))
                {
                    writer.Write(Encoding.ASCII.GetBytes("Salted__"));
                    writer.Write(saltBytes);
                    writer.Write(encrypter.TransformFinalBlock(keyDecrypted, 0, keyDecrypted.Length));
                    writer.Flush();
                    Response.Write(conv.Serialize(new
                    {
                        challenge = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length)
                    }));
                }
                Response.ContentType = "application/json";
                Response.End();
            }
            else if (Request.Form["jCryption"] != null)
            {
                NameValueCollection tempForm;
                var keyDecrypted = (byte[])Session["_key"];
                if (keyDecrypted == null)
                {
                    Response.StatusCode = 412;
                    Response.End();
                }
                var jCryption = Convert.FromBase64String(Request.Form["jCryption"]);
                var reader = new System.IO.BinaryReader(new System.IO.MemoryStream(jCryption));
                var saltMark = reader.ReadBytes(8);
                var saltBytes = reader.ReadBytes(8);
                var kd = new OpenSslCompatDeriveBytes(keyDecrypted, saltBytes, "MD5", 1);
                var aesProvider = new AesCryptoServiceProvider();
                var decryptor = aesProvider.CreateDecryptor(kd.GetBytes(aesProvider.KeySize / 8), kd.GetBytes(aesProvider.BlockSize / 8));
                using (var cs = new CryptoStream(reader.BaseStream, decryptor, CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs))
                {
                    tempForm = HttpUtility.ParseQueryString(sr.ReadToEnd());
                }
                //
                var collection = HttpContext.Current.Request.Form;
                // Get the "IsReadOnly" protected instance property.
                var propInfo = collection.GetType().GetProperty("IsReadOnly", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                // Mark the collection as NOT "IsReadOnly"
                propInfo.SetValue(collection, false, new object[] { });
                foreach (var k in tempForm.AllKeys)
                {
                    collection[k] = tempForm[k];
                }
                propInfo.SetValue(collection, true, new object[] { });
                //
            }
        }
    }
    /// <summary>
    /// Derives a key from a password using an OpenSSL-compatible version of the PBKDF1 algorithm.
    /// </summary>
    /// <remarks>
    /// based on the OpenSSL EVP_BytesToKey method for generating key and iv
    /// http://www.openssl.org/docs/crypto/EVP_BytesToKey.html
    /// </remarks>
    public class OpenSslCompatDeriveBytes : DeriveBytes
    {
        private readonly byte[] _data;
        private readonly HashAlgorithm _hash;
        private readonly int _iterations;
        private readonly byte[] _salt;
        private byte[] _currentHash;
        private int _hashListReadIndex;
        private List<byte> _hashList;

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSslCompat.OpenSslCompatDeriveBytes"/> class specifying the password, key salt, hash name, and iterations to use to derive the key.
        /// </summary>
        /// <param name="password">The password for which to derive the key.</param>
        /// <param name="salt">The key salt to use to derive the key.</param>
        /// <param name="hashName">The name of the hash algorithm for the operation. (e.g. MD5 or SHA1)</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        public OpenSslCompatDeriveBytes(string password, byte[] salt, string hashName, int iterations)
            : this(new UTF8Encoding(false).GetBytes(password), salt, hashName, iterations)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSslCompat.OpenSslCompatDeriveBytes"/> class specifying the password, key salt, hash name, and iterations to use to derive the key.
        /// </summary>
        /// <param name="password">The password for which to derive the key.</param>
        /// <param name="salt">The key salt to use to derive the key.</param>
        /// <param name="hashName">The name of the hash algorithm for the operation. (e.g. MD5 or SHA1)</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        public OpenSslCompatDeriveBytes(byte[] password, byte[] salt, string hashName, int iterations)
        {
            if (iterations <= 0)
                throw new ArgumentOutOfRangeException("iterations", iterations, "iterations is out of range. Positive number required");

            _data = password;
            _salt = salt;
            _hash = HashAlgorithm.Create(hashName);
            _iterations = iterations;
        }

        /// <summary>
        /// Returns a pseudo-random key from a password, salt and iteration count.
        /// </summary>
        /// <param name="cb">The number of pseudo-random key bytes to generate.</param>
        /// <returns>A byte array filled with pseudo-random key bytes.</returns>
        public override byte[] GetBytes(int cb)
        {
            if (cb <= 0)
                throw new ArgumentOutOfRangeException("cb", cb, "cb is out of range. Positive number required.");

            if (_currentHash == null)
            {
                _hashList = new List<byte>();
                _currentHash = new byte[0];
                _hashListReadIndex = 0;

                int preHashLength = _data.Length + ((_salt != null) ? _salt.Length : 0);
                var preHash = new byte[preHashLength];

                System.Buffer.BlockCopy(_data, 0, preHash, 0, _data.Length);
                if (_salt != null)
                    System.Buffer.BlockCopy(_salt, 0, preHash, _data.Length, _salt.Length);

                _currentHash = _hash.ComputeHash(preHash);

                for (int i = 1; i < _iterations; i++)
                {
                    _currentHash = _hash.ComputeHash(_currentHash);
                }

                _hashList.AddRange(_currentHash);
            }

            while (_hashList.Count < (cb + _hashListReadIndex))
            {
                int preHashLength = _currentHash.Length + _data.Length + ((_salt != null) ? _salt.Length : 0);
                var preHash = new byte[preHashLength];

                System.Buffer.BlockCopy(_currentHash, 0, preHash, 0, _currentHash.Length);
                System.Buffer.BlockCopy(_data, 0, preHash, _currentHash.Length, _data.Length);
                if (_salt != null)
                    System.Buffer.BlockCopy(_salt, 0, preHash, _currentHash.Length + _data.Length, _salt.Length);

                _currentHash = _hash.ComputeHash(preHash);

                for (int i = 1; i < _iterations; i++)
                {
                    _currentHash = _hash.ComputeHash(_currentHash);
                }

                _hashList.AddRange(_currentHash);
            }

            byte[] dst = new byte[cb];
            _hashList.CopyTo(_hashListReadIndex, dst, 0, cb);
            _hashListReadIndex += cb;

            return dst;
        }

        /// <summary>
        /// Resets the state of the operation.
        /// </summary>
        public override void Reset()
        {
            _hashListReadIndex = 0;
            _currentHash = null;
            _hashList = null;
        }
    }

    /// <summary>
    /// ASPX page
    /// </summary>
    public class SecurePage : System.Web.UI.Page 
    {
#if true // case for automatically created RSA key ( recommended )
        static RSACryptoServiceProvider cryptoProvider = new RSACryptoServiceProvider(1024);
#elif true // using .NET style exported RSA key in XML format
        String rsa_1024_pub_xml = "~/App_Data/rsa_1024_pub.xml";
        String rsa_1024_priv_xml = "~/App_Data/rsa_1024_priv.xml";
        RSACryptoServiceProvider _cryptoProvider = null;
        RSACryptoServiceProvider cryptoProvider {
            get
            {
                if( _cryptoProvider == null ){
                    _cryptoProvider = new RSACryptoServiceProvider();
                    _cryptoProvider.FromXmlString(System.IO.File.ReadAllText(Server.MapPath(rsa_1024_priv_xml)));
                }
                return _cryptoProvider;
            }
        }

#else // using OpenSSL exprted pem file (as written in the original PHP implementation)
        String rsa_1024_pub = "rsa_1024_pub.pem";
        String rsa_1024_priv = "rsa_1024_priv.pem";
        RSACryptoServiceProvider _cryptoProvider = null;
        RSACryptoServiceProvider cryptoProvider
        {
            get
            {
                if (_cryptoProvider == null)
                {
                    var pemBytes = Utility.DecodeOpenSSLPrivateKey(System.IO.File.ReadAllText(Server.MapPath("./" + rsa_1024_priv)));
                    _cryptoProvider = new RSACryptoServiceProvider();
                    _cryptoProvider.ImportParameters( Utility.DecodeRSAPrivateKey(pemBytes) );
                }
                return _cryptoProvider;
            }
        }

#endif

        protected override void OnPreInit(EventArgs e)
        {
            base.OnPreInit(e);
            if( ! Request.IsSecureConnection )
                Utility.ProcessRequest(new HttpContextWrapper(Context), cryptoProvider);
        }
    }

    /// <summary>
    /// Summary description for jCryption
    /// </summary>
    public static class jCryption
    {
        static RSACryptoServiceProvider cryptoProvider = new RSACryptoServiceProvider(1024);
        /// <summary>
        /// declare to handle request to respond to RSA public key exchange.
        /// This method call should be placed on top of cshtml.
        /// </summary>
        /// <param name="request">WePages' Request object</param>
        public static void HandleRequest(HttpRequestBase request)
        {
            global::jCryption.Utility.ProcessRequest(request.RequestContext.HttpContext, cryptoProvider);
        }
        /// <summary>
        /// renders a script block to call $.jCryption activation with a formSelector
        /// </summary>
        /// <example>
        /// @jCryptionScriptForm("form#login")
        /// </example>
        /// <param name="formSelector">jQuery selector, which specifies the 'form' element.</param>
        /// <returns></returns>
        public static IHtmlString RenderScriptFor(String formSelector, String pathToJS = null )
        {
            if (HttpContext.Current.Request.IsSecureConnection) return null;
            var path = HttpContext.Current.Request.Path;
            return new HtmlString( ( pathToJS == null ? "" : @"<script type=""text/javascript"" src=""" + pathToJS + @"""></script>" ) +
                @"
        <script type=""text/javascript"">
        $(document).ready(function () {
        var form = $('" + formSelector + @"'), hasValidator = !!form.data('validator');
        if (hasValidator) {
            var v = form.validate();
            v.settings.submitHandler = function (_form, event) {
                var form = $(_form);
                if (!form.hasClass('jc-before-submit')) {
                    v.settings.submitHandler = null;
                    form.addClass('jc-before-submit');
                    form.trigger('_jc_submit', event);
                }
            };
        }
        form.jCryption({
            getKeysURL: '" + path + @"?getPublicKey=true',
            handshakeURL: '" + path + @"?handshake=true',
            submitElement: hasValidator ? form : false,
            submitEvent: hasValidator ? '_jc_submit' : 'click'
        });
    }); </script>"
                             );
        }
    }
}
