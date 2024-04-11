package x509

import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder
import org.bouncycastle.operator.*
import org.bouncycastle.operator.bc.BcContentSignerBuilder
import org.bouncycastle.operator.bc.BcECContentSignerBuilder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.StringWriter
import java.math.BigInteger
import java.net.InetAddress
import java.net.UnknownHostException
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*


object X509Helper {
    init {
        Security.removeProvider("BC")
        Security.insertProviderAt(BouncyCastleProvider(), 0)
    }

    private val PRNG = SecureRandom()
    private val DEFAULT_RSA_KEY_SIZE_BITS = 2048
    private val DEFAULT_RSA_PUB_EXPONENT: BigInteger = RSAKeyGenParameterSpec.F4 // 65537
    private val DEFAULT_ELLIPTIC_CURVE_NAME = "secp256r1"

    // Per RFC 5280 section 4.1.2.2, X509 certificates can use up to 20 bytes == 160 bits for serial numbers.
    private val SERIAL_NUMBER_MAX_BITS = 20 * java.lang.Byte.SIZE

    /**
     * Signs the certificate being built by the given builder using the given private key and returns the certificate.
     * @param privateKey the private key to sign the certificate with.
     * @param builder the cert builder that contains the certificate data.
     * @return the signed certificate.
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    @Throws(IOException::class, OperatorCreationException::class, CertificateException::class)
    private fun buildAndSignCertificate(
        privateKey: PrivateKey, builder: X509v3CertificateBuilder
    ): X509Certificate {
        val signerBuilder: BcContentSignerBuilder
        if (privateKey.algorithm.contains("RSA")) { // a little hacky way to detect key type, but it works
            val signatureAlgorithm = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption")
            val digestAlgorithm = DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm)
            signerBuilder = BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm)
        } else { // if not RSA, assume EC
            val signatureAlgorithm = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA")
            val digestAlgorithm = DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm)
            signerBuilder = BcECContentSignerBuilder(signatureAlgorithm, digestAlgorithm)
        }
        val privateKeyParam: AsymmetricKeyParameter = PrivateKeyFactory.createKey(privateKey.encoded)
        val signer: ContentSigner = signerBuilder.build(privateKeyParam)
        return toX509Cert(builder.build(signer))
    }

    /**
     * Uses the private key of the given key pair to create a self-signed CA certificate with the public half of the
     * key pair and the given subject and expiration. The issuer of the new cert will be equal to the subject.
     * Returns the new certificate.
     * The returned certificate should be used as the trust store. The private key of the input key pair should be
     * used to sign certificates that are used by test peers to establish TLS connections to each other.
     * @param subject the subject of the new certificate being created.
     * @param keyPair the key pair to use. The public key will be embedded in the new certificate, and the private key
     * will be used to self-sign the certificate.
     * @param expirationMillis expiration of the new certificate, in milliseconds from now.
     * @return a new self-signed CA certificate.
     * @throws IOException
     * @throws OperatorCreationException
     * @throws GeneralSecurityException
     */
    @Throws(IOException::class, OperatorCreationException::class, GeneralSecurityException::class)
    fun newSelfSignedCACert(
        subject: X500Name, keyPair: KeyPair, expirationMillis: Long
    ): X509Certificate {
        val notBefore = Date()
        val notAfter = Date(notBefore.time + expirationMillis)
        val builder = initCertBuilder(
            subject,  // for self-signed certs, issuer == subject
            notBefore,
            notAfter,
            subject,
            keyPair.public
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true)) // is a CA
        builder.addExtension(
            Extension.keyUsage,
            true,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign)
        )
        return buildAndSignCertificate(keyPair.private, builder)
    }

    /**
     * Helper method for newSelfSignedCACert() and newCert(). Initializes a X509v3CertificateBuilder with
     * logic that's common to both methods.
     * @param issuer Issuer field of the new cert.
     * @param notBefore date before which the new cert is not valid.
     * @param notAfter date after which the new cert is not valid.
     * @param subject Subject field of the new cert.
     * @param subjectPublicKey public key to store in the new cert.
     * @return a X509v3CertificateBuilder that can be further customized to finish creating the new cert.
     */
    private fun initCertBuilder(
        issuer: X500Name, notBefore: Date, notAfter: Date, subject: X500Name, subjectPublicKey: PublicKey
    ): X509v3CertificateBuilder {
        return X509v3CertificateBuilder(
            issuer,
            BigInteger(SERIAL_NUMBER_MAX_BITS, PRNG),
            notBefore,
            notAfter,
            subject,
            SubjectPublicKeyInfo.getInstance(subjectPublicKey.encoded)
        )
    }

    /**
     * Returns subject alternative names for "localhost".
     * @return the subject alternative names for "localhost".
     */
    @Throws(UnknownHostException::class)
    private fun getLocalhostSubjectAltNames(): GeneralNames {
        val localAddresses = InetAddress.getAllByName("localhost")
        val generalNames: Array<GeneralName?> = arrayOfNulls<GeneralName>(localAddresses.size + 1)
        for (i in localAddresses.indices) {
            generalNames[i] = GeneralName(GeneralName.iPAddress, DEROctetString(localAddresses[i].address))
        }
        generalNames[generalNames.size - 1] = GeneralName(GeneralName.dNSName, DERIA5String("localhost"))
        return GeneralNames(generalNames)
    }

    /**
     * Using the private key of the given CA key pair and the Subject of the given CA cert as the Issuer, issues a
     * new cert with the given subject and public key. The returned certificate, combined with the private key half
     * of the `certPublicKey`, should be used as the key store.
     * @param caCert the certificate of the CA that's doing the signing.
     * @param caKeyPair the key pair of the CA. The private key will be used to sign. The public key must match the
     * public key in the `caCert`.
     * @param certSubject the subject field of the new cert being issued.
     * @param certPublicKey the public key of the new cert being issued.
     * @param expirationMillis the expiration of the cert being issued, in milliseconds from now.
     * @return a new certificate signed by the CA's private key.
     * @throws IOException
     * @throws OperatorCreationException
     * @throws GeneralSecurityException
     */
    @Throws(IOException::class, OperatorCreationException::class, GeneralSecurityException::class)
    fun newCert(
        caCert: X509Certificate,
        caKeyPair: KeyPair,
        certSubject: X500Name,
        certPublicKey: PublicKey,
        expirationMillis: Long
    ): X509Certificate {
        require(caKeyPair.public == caCert.publicKey) { "CA private key does not match the public key in the CA cert" }
        val notBefore = Date()
        val notAfter = Date(notBefore.time + expirationMillis)
        val x500Name = X500Name(caCert.getIssuerX500Principal().name)
        val builder = initCertBuilder(
            x500Name,
            notBefore,
            notAfter,
            certSubject,
            certPublicKey
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false)) // not a CA
        builder.addExtension(
            Extension.keyUsage, true, KeyUsage(
                KeyUsage.digitalSignature
                        or KeyUsage.keyEncipherment
            )
        )
        builder.addExtension(
            Extension.extendedKeyUsage,
            true,
            ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth))
        )

        builder.addExtension(Extension.subjectAlternativeName, false, getLocalhostSubjectAltNames())
        return buildAndSignCertificate(caKeyPair.private, builder)
    }

    /**
     * Generates a new asymmetric key pair of the given type.
     * @param keyType the type of key pair to generate.
     * @return the new key pair.
     * @throws GeneralSecurityException if your java crypto providers are messed up.
     */
    @Throws(GeneralSecurityException::class)
    fun generateKeyPair(keyType: X509KeyType?): KeyPair {
        return when (keyType) {
            X509KeyType.RSA -> generateRSAKeyPair()
            X509KeyType.EC -> generateECKeyPair()
            else -> throw IllegalArgumentException("Invalid X509KeyType")
        }
    }

    /**
     * Generates an RSA key pair with a 2048-bit private key and F4 (65537) as the public exponent.
     * @return the key pair.
     */
    @Throws(GeneralSecurityException::class)
    fun generateRSAKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        val keyGenSpec = RSAKeyGenParameterSpec(DEFAULT_RSA_KEY_SIZE_BITS, DEFAULT_RSA_PUB_EXPONENT)
        keyGen.initialize(keyGenSpec, PRNG)
        return keyGen.generateKeyPair()
    }

    /**
     * Generates an elliptic curve key pair using the "secp256r1" aka "prime256v1" aka "NIST P-256" curve.
     * @return the key pair.
     */
    @Throws(GeneralSecurityException::class)
    fun generateECKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("EC")
        keyGen.initialize(ECGenParameterSpec(DEFAULT_ELLIPTIC_CURVE_NAME), PRNG)
        return keyGen.generateKeyPair()
    }

    /**
     * PEM-encodes the given X509 certificate and private key (compatible with OpenSSL), optionally protecting the
     * private key with a password. Concatenates them both and returns the result as a single string.
     * This creates the PEM encoding of a key store.
     * @param cert the X509 certificate to PEM-encode.
     * @param privateKey the private key to PEM-encode.
     * @param keyPassword an optional key password. If empty or null, the private key will not be encrypted.
     * @return a String containing the PEM encodings of the certificate and private key.
     * @throws IOException if converting the certificate or private key to PEM format fails.
     * @throws OperatorCreationException if constructing the encryptor from the given password fails.
     */
    @Throws(IOException::class, OperatorCreationException::class)
    fun pemEncodeCertAndPrivateKey(
        cert: X509Certificate?, privateKey: PrivateKey?, keyPassword: String?
    ): String {
        return """
              ${pemEncodeX509Certificate(cert)}
              ${pemEncodePrivateKey(privateKey, keyPassword)}
              """.trimIndent()
    }

    /**
     * PEM-encodes the given private key (compatible with OpenSSL), optionally protecting it with a password, and
     * returns the result as a String.
     * @param key the private key.
     * @param password an optional key password. If empty or null, the private key will not be encrypted.
     * @return a String containing the PEM encoding of the private key.
     * @throws IOException if converting the key to PEM format fails.
     * @throws OperatorCreationException if constructing the encryptor from the given password fails.
     */
    @Throws(IOException::class, OperatorCreationException::class)
    fun pemEncodePrivateKey(
        key: PrivateKey?, password: String?
    ): String {
        val stringWriter = StringWriter()
        val pemWriter = JcaPEMWriter(stringWriter)
        var encryptor: OutputEncryptor? = null
        if (password != null && password.length > 0) {
            encryptor =
                JceOpenSSLPKCS8EncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC).setProvider(
                    BouncyCastleProvider.PROVIDER_NAME
                ).setRandom(PRNG).setPassword(password.toCharArray()).build()
        }
        pemWriter.writeObject(JcaPKCS8Generator(key, encryptor))
        pemWriter.close()
        return stringWriter.toString()
    }

    /**
     * PEM-encodes the given X509 certificate (compatible with OpenSSL) and returns the result as a String.
     * @param cert the certificate.
     * @return a String containing the PEM encoding of the certificate.
     * @throws IOException if converting the certificate to PEM format fails.
     */
    @Throws(IOException::class)
    fun pemEncodeX509Certificate(cert: X509Certificate?): String {
        val stringWriter = StringWriter()
        val pemWriter = JcaPEMWriter(stringWriter)
        pemWriter.writeObject(cert)
        pemWriter.close()
        return stringWriter.toString()
    }

    /**
     * Encodes the given X509Certificate as a JKS TrustStore, optionally protecting the cert with a password (though
     * it's unclear why one would do this since certificates only contain public information and do not need to be
     * kept secret). Returns the byte array encoding of the trust store, which may be written to a file and loaded to
     * instantiate the trust store at a later point or in another process.
     * @param cert the certificate to serialize.
     * @param keyPassword an optional password to encrypt the trust store. If empty or null, the cert will not be encrypted.
     * @return the serialized bytes of the JKS trust store.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun certToJavaTrustStoreBytes(
        cert: X509Certificate, keyPassword: String?
    ): ByteArray {
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
        return certToTrustStoreBytes(cert, keyPassword, trustStore)
    }

    /**
     * Encodes the given X509Certificate as a PKCS12 TrustStore, optionally protecting the cert with a password (though
     * it's unclear why one would do this since certificates only contain public information and do not need to be
     * kept secret). Returns the byte array encoding of the trust store, which may be written to a file and loaded to
     * instantiate the trust store at a later point or in another process.
     * @param cert the certificate to serialize.
     * @param keyPassword an optional password to encrypt the trust store. If empty or null, the cert will not be encrypted.
     * @return the serialized bytes of the PKCS12 trust store.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun certToPKCS12TrustStoreBytes(
        cert: X509Certificate, keyPassword: String?
    ): ByteArray {
        val trustStore = KeyStore.getInstance("PKCS12")
        return certToTrustStoreBytes(cert, keyPassword, trustStore)
    }

    /**
     * Encodes the given X509Certificate as a BCFKS TrustStore, optionally protecting the cert with a password (though
     * it's unclear why one would do this since certificates only contain public information and do not need to be
     * kept secret). Returns the byte array encoding of the trust store, which may be written to a file and loaded to
     * instantiate the trust store at a later point or in another process.
     * @param cert the certificate to serialize.
     * @param keyPassword an optional password to encrypt the trust store. If empty or null, the cert will not be encrypted.
     * @return the serialized bytes of the BCFKS trust store.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun certToBCFKSTrustStoreBytes(
        cert: X509Certificate,
        keyPassword: String?
    ): ByteArray {
        val trustStore = KeyStore.getInstance("BCFKS")
        return certToTrustStoreBytes(cert, keyPassword, trustStore)
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    private fun certToTrustStoreBytes(cert: X509Certificate, keyPassword: String?, trustStore: KeyStore): ByteArray {
        val keyPasswordChars = keyPassword?.toCharArray() ?: CharArray(0)
        trustStore.load(null, keyPasswordChars)
        trustStore.setCertificateEntry(cert.subjectDN.toString(), cert)
        val outputStream = ByteArrayOutputStream()
        trustStore.store(outputStream, keyPasswordChars)
        outputStream.flush()
        val result = outputStream.toByteArray()
        outputStream.close()
        return result
    }

    /**
     * Encodes the given X509Certificate and private key as a JKS KeyStore, optionally protecting the private key
     * (and possibly the cert?) with a password. Returns the byte array encoding of the key store, which may be written
     * to a file and loaded to instantiate the key store at a later point or in another process.
     * @param cert the X509 certificate to serialize.
     * @param privateKey the private key to serialize.
     * @param keyPassword an optional key password. If empty or null, the private key will not be encrypted.
     * @return the serialized bytes of the JKS key store.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun certAndPrivateKeyToJavaKeyStoreBytes(
        cert: X509Certificate, privateKey: PrivateKey, keyPassword: String?
    ): ByteArray {
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
        return certAndPrivateKeyToBytes(cert, privateKey, keyPassword, keyStore)
    }

    /**
     * Encodes the given X509Certificate and private key as a PKCS12 KeyStore, optionally protecting the private key
     * (and possibly the cert?) with a password. Returns the byte array encoding of the key store, which may be written
     * to a file and loaded to instantiate the key store at a later point or in another process.
     * @param cert the X509 certificate to serialize.
     * @param privateKey the private key to serialize.
     * @param keyPassword an optional key password. If empty or null, the private key will not be encrypted.
     * @return the serialized bytes of the PKCS12 key store.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun certAndPrivateKeyToPKCS12Bytes(
        cert: X509Certificate, privateKey: PrivateKey, keyPassword: String?
    ): ByteArray {
        val keyStore = KeyStore.getInstance("PKCS12")
        return certAndPrivateKeyToBytes(cert, privateKey, keyPassword, keyStore)
    }

    /**
     * Encodes the given X509Certificate and private key as a BCFKS KeyStore, optionally protecting the private key
     * (and possibly the cert?) with a password. Returns the byte array encoding of the key store, which may be written
     * to a file and loaded to instantiate the key store at a later point or in another process.
     * @param cert the X509 certificate to serialize.
     * @param privateKey the private key to serialize.
     * @param keyPassword an optional key password. If empty or null, the private key will not be encrypted.
     * @return the serialized bytes of the BCFKS key store.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun certAndPrivateKeyToBCFKSBytes(
        cert: X509Certificate,
        privateKey: PrivateKey,
        keyPassword: String?
    ): ByteArray {
        val keyStore = KeyStore.getInstance("BCFKS")
        return certAndPrivateKeyToBytes(cert, privateKey, keyPassword, keyStore)
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    private fun certAndPrivateKeyToBytes(
        cert: X509Certificate, privateKey: PrivateKey, keyPassword: String?, keyStore: KeyStore
    ): ByteArray {
        val keyPasswordChars = keyPassword?.toCharArray() ?: CharArray(0)
        keyStore.load(null, keyPasswordChars)
        keyStore.setKeyEntry("key", privateKey, keyPasswordChars, arrayOf(cert))
        val outputStream = ByteArrayOutputStream()
        keyStore.store(outputStream, keyPasswordChars)
        outputStream.flush()
        val result = outputStream.toByteArray()
        outputStream.close()
        return result
    }

    /**
     * Convenience method to convert a bouncycastle X509CertificateHolder to a java X509Certificate.
     * @param certHolder a bouncycastle X509CertificateHolder.
     * @return a java X509Certificate
     * @throws CertificateException if the conversion fails.
     */
    @Throws(CertificateException::class)
    fun toX509Cert(certHolder: X509CertificateHolder?): X509Certificate {
        return JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder)
    }
}

enum class X509KeyType {
    RSA,
    EC
}