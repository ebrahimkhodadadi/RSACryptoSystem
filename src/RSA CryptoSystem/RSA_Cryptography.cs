using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RSA;

/// <summary>
/// <PackageReference Include="BouncyCastle.NetCore" Version="1.8.5" />
/// https://www.idc-online.com/technical_references/pdfs/information_technology/Bouncy_Castle_Net_Implementation_RSA_Algorithm.pdf
/// https://cryptotools.net/rsagen
/// </summary>
public class RSA_Cryptography
{
    /// <summary>
    /// Generate RSA Key
    /// </summary>
    /// <param name="strength"></param>
    /// <returns></returns>
    public static (string publicKey, string privateKey) GenerateKeys(int strength = 1024)
    {
        //Generate 1024 Key Pair
        var kpgen = new RsaKeyPairGenerator();
        kpgen.Init(new KeyGenerationParameters(new SecureRandom(), strength));
        var keyPair = kpgen.GenerateKeyPair();


        //Write publickey in Pem Format
        TextWriter textWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(textWriter);
        pemWriter.WriteObject(keyPair.Public);
        pemWriter.Writer.Flush();
        string publicKey = textWriter.ToString();

        //Write privatekey in Pem Format
        TextWriter textWriter1 = new StringWriter();
        PemWriter pemWriter1 = new PemWriter(textWriter1);
        pemWriter1.WriteObject(keyPair.Private);
        pemWriter1.Writer.Flush();
        string current_privateKey = textWriter1.ToString();

        return (publicKey, current_privateKey);
    }

    #region Verify
    /// <summary>
    /// Generate signature with private key
    /// </summary>
    /// <param name="model">it can be any object</param>
    /// <param name="privateKey">rsa private key</param>
    /// <returns></returns>
    public static string VerifySignature(object model, string privateKey)
    {
        string textPlain = JsonConvert.SerializeObject(model);

        var rsav = new RsaSignAndVerify();
        var rsaPrivateKey = rsav.ImportPrivateKey(privateKey);
        var signature = rsav.ServerGenerateSignature(textPlain, (RsaKeyParameters)rsaPrivateKey);
        return Convert.ToBase64String(signature);
    }
    /// <summary>
    /// Is signature valid with public key
    /// </summary>
    /// <param name="model">the exect object that server generate signature for it</param>
    /// <param name="signature">server generated signutre</param>
    /// <param name="publicKey">rsa public key</param>
    /// <returns></returns>
    public static bool ClientValidateSignature(object model, string signature, string publicKey)
    {
        var textPlain = JsonConvert.SerializeObject(model);

        var rsav = new RsaSignAndVerify();
        var rsaPublicKey = rsav.ImportPublicKey(publicKey);
        var signatureByte = Convert.FromBase64String(signature);
        var isSignatureValid = rsav.ClientValidateSignature(textPlain.ToString(), signatureByte, (RsaKeyParameters)rsaPublicKey);
        return isSignatureValid;
    }
    #endregion

    #region Encrypt & Decrypt

    /// <summary>
    /// Decrypt object
    /// </summary>
    /// <param name="base64Input">signutre</param>
    /// <param name="privateKey">private key</param>
    /// <returns></returns>
    public static string RsaDecryptWithPrivate(string base64Input, string privateKey)
    {
        //Encode text to bytes
        var bytesToDecrypt = Convert.FromBase64String(base64Input);
        //Initialize Rsa Engine
        var decryptEngine = new Pkcs1Encoding(new RsaEngine());

        //Read Pem
        using (var txtreader = new StringReader(privateKey))
        {
            //cast privatekey to asymmetric cipher keypair because rsa private key always contains public key
            var keyParameter = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();

            //Set engine for decryption
            decryptEngine.Init(false, keyParameter.Private);
        }

        // decrypt bytes block and converts it to Utf8 string
        var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));

        //Return decrypted string
        return decrypted;
    }

    /// <summary>
    /// Encrypt object
    /// </summary>
    /// <param name="model">object</param>
    /// <param name="publicKey">public key</param>
    /// <returns></returns>
    public static string RsaEncryptWithPublic(object model, string publicKey)
    {
        // serilize to json
        string clearText = JsonConvert.SerializeObject(model);

        //Encode text to bytes
        var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

        //Initialize Rsa Engine
        var encryptEngine = new Pkcs1Encoding(new RsaEngine());

        //Read pem 
        using (var txtreader = new StringReader(publicKey))
        {
            //cast publickey to asymmetric key parameter
            var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();

            //Set engine for encryption( true means that parameter is used for encryption)
            encryptEngine.Init(true, keyParameter);
        }

        // encrypt bytes block and converts it to base64string
        var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));

        //Return decrypted string
        return encrypted;

    }

    #endregion
}

public class RsaSignAndVerify
{
    public AsymmetricKeyParameter ImportPrivateKey(string pem)
    {
        PemReader pr = new PemReader(new StringReader(pem));
        AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
        return KeyPair.Private;
    }
    public AsymmetricKeyParameter ImportPublicKey(string pem)
    {
        PemReader pr = new PemReader(new StringReader(pem));
        AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
        return publicKey;
    }

    public AsymmetricCipherKeyPair GenerateRandomKeyPair()
    {
        var rsaKeyPairGen = new RsaKeyPairGenerator();
        rsaKeyPairGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
        return rsaKeyPairGen.GenerateKeyPair(); ;
    }

    public bool ClientValidateSignature(string sourceData, byte[] signature, RsaKeyParameters publicKey)
    {
        byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);

        ISigner signClientSide = SignerUtilities.GetSigner(PkcsObjectIdentifiers.IdRsassaPss.Id);
        signClientSide.Init(false, publicKey);
        signClientSide.BlockUpdate(tmpSource, 0, tmpSource.Length);

        return signClientSide.VerifySignature(signature);
    }

    public byte[] ServerGenerateSignature(string sourceData, RsaKeyParameters privateKey)
    {
        byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);

        ISigner sign = SignerUtilities.GetSigner(PkcsObjectIdentifiers.IdRsassaPss.Id);
        sign.Init(true, privateKey);
        sign.BlockUpdate(tmpSource, 0, tmpSource.Length);
        return sign.GenerateSignature();
    }

    public void PrintKeys(AsymmetricCipherKeyPair keyPair)
    {
        using (TextWriter textWriter1 = new StringWriter())
        {
            var pemWriter1 = new PemWriter(textWriter1);
            pemWriter1.WriteObject(keyPair.Private);
            pemWriter1.Writer.Flush();

            string privateKey = textWriter1.ToString();
            Console.WriteLine(privateKey);
        }

        using (TextWriter textWriter2 = new StringWriter())
        {
            var pemWriter2 = new PemWriter(textWriter2);
            pemWriter2.WriteObject(keyPair.Public);
            pemWriter2.Writer.Flush();
            string publicKey = textWriter2.ToString();
            Console.WriteLine(publicKey);
        }
    }

    private byte[] ConvertHexString(string hexString)
    {
        byte[] data = new byte[hexString.Length / 2];
        for (int index = 0; index < data.Length; index++)
        {
            string byteValue = hexString.Substring(index * 2, 2);
            data[index] = byte.Parse(byteValue, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
        }

        return data;
    }
    public RSACryptoServiceProvider RsaProviderFromPrivateKeyInPemFile(string privateKeyPath)
    {
        using (TextReader privateKeyTextReader = new StringReader(privateKeyPath))
        {
            PemReader pr = new PemReader(privateKeyTextReader);
            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            csp.ImportParameters(rsaParams);
            return csp;
        }
    }
}