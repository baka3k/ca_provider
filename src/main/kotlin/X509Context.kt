import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.lang.invoke.MethodHandles
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Arrays

import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * This class simplifies the creation of certificates and private keys for SSL/TLS connections.
 */
class X509Context(
    private val tempDir: File,

    private val trustStoreKeyPair: KeyPair,
    private val trustStoreCertExpirationMillis: Long = 0,
    private val trustStorePassword: String = "",
    private var trustStoreJksFile: File? = null,
    private var trustStorePemFile: File? = null,
    private var trustStorePkcs12File: File? = null,
    private var trustStoreBcfksFile: File? = null,
    private val keyStoreKeyPair: KeyPair,
    private val keyStoreCertExpirationMillis: Long = 0,
    private val keyStorePassword: String = "",
    private var keyStoreJksFile: File? = null,
    private var keyStorePemFile: File? = null,
    private var keyStorePkcs12File: File? = null,
    private var keyStoreBcfksFile: File? = null,
    private val hostnameVerification: Boolean = false
) {
    private val trustStoreCertificate: X509Certificate
    private val keyStoreCertificate: X509Certificate
    private val trustStoreKeyType: X509KeyType
    private val keyStoreKeyType: X509KeyType

    companion object {
        private const val TRUST_STORE_PREFIX = "zk_test_ca"
        private const val KEY_STORE_PREFIX = "zk_test_key"

        /**
         * Returns the X509KeyType of the given key pair.
         * @param keyPair the key pair.
         * @return <code>X509KeyType.RSA</code> if given an RSA key pair, and <code>X509KeyType.EC</code> otherwise.
         */
        private fun keyPairToType(keyPair: KeyPair): X509KeyType {
            return if (keyPair.private.algorithm.contains("RSA")) {
                X509KeyType.RSA
            } else {
                X509KeyType.EC
            }
        }
    }

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            throw IllegalStateException("BC Security provider was not found")
        }
        require(tempDir.isDirectory) { "Not a directory: $tempDir" }

        trustStoreKeyType = keyPairToType(trustStoreKeyPair)
        keyStoreKeyType = keyPairToType(keyStoreKeyPair)

        val caNameBuilder = X500NameBuilder(BCStyle.INSTANCE)
        caNameBuilder.addRDN(BCStyle.CN, MethodHandles.lookup().lookupClass().canonicalName + " Root CA")
        println(MethodHandles.lookup().lookupClass().canonicalName + " Root CA")
        println(caNameBuilder.build())
        trustStoreCertificate =
            X509Helper.newSelfSignedCACert(caNameBuilder.build(), trustStoreKeyPair, trustStoreCertExpirationMillis)
        val nameBuilder = X500NameBuilder(BCStyle.INSTANCE)
        nameBuilder.addRDN(BCStyle.CN, MethodHandles.lookup().lookupClass().canonicalName + " Zookeeper Test")
        keyStoreCertificate = X509Helper.newCert(
            trustStoreCertificate,
            trustStoreKeyPair,
            nameBuilder.build(),
            keyStoreKeyPair.public,
            keyStoreCertExpirationMillis
        )
    }

    fun getTempDir(): File {
        return tempDir
    }

    fun getTrustStoreKeyType(): X509KeyType {
        return trustStoreKeyType
    }

    fun getTrustStoreKeyPair(): KeyPair {
        return trustStoreKeyPair
    }

    fun getTrustStoreCertExpirationMillis(): Long {
        return trustStoreCertExpirationMillis
    }

    fun getTrustStoreCertificate(): X509Certificate {
        return trustStoreCertificate
    }

    fun getTrustStorePassword(): String {
        return trustStorePassword
    }

    /**
     * Returns the path to the trust store file in the given format (JKS or PEM). Note that the file is created lazily,
     * the first time this method is called. The trust store file is temporary and will be deleted on exit.
     * @param storeFileType the store file type (JKS or PEM).
     * @return the path to the trust store file.
     * @throws IOException if there is an error creating the trust store file.
     */
    @Throws(IOException::class)
    fun getTrustStoreFile(storeFileType: KeyStoreFileType): File {
        return when (storeFileType) {
            KeyStoreFileType.JKS -> getTrustStoreJksFile()
            KeyStoreFileType.PEM -> getTrustStorePemFile()
            KeyStoreFileType.PKCS12 -> getTrustStorePkcs12File()
            KeyStoreFileType.BCFKS -> getTrustStoreBcfksFile()
            else -> throw IllegalArgumentException(
                "Invalid trust store type: $storeFileType, must be one of: ${
                    Arrays.toString(
                        KeyStoreFileType.values()
                    )
                }"
            )
        }
    }

    @Throws(IOException::class)
    private fun getTrustStoreJksFile(): File {
        if (trustStoreJksFile == null) {
            val trustStoreJksFile =
                File.createTempFile(TRUST_STORE_PREFIX, KeyStoreFileType.JKS.defaultFileExtension, tempDir)
            trustStoreJksFile.deleteOnExit()
            FileOutputStream(trustStoreJksFile).use { trustStoreOutputStream ->
                val bytes = X509Helper.certToJavaTrustStoreBytes(trustStoreCertificate, trustStorePassword)
                trustStoreOutputStream.write(bytes)
                trustStoreOutputStream.flush()
            }
            this.trustStoreJksFile = trustStoreJksFile
        }
        return trustStoreJksFile!!
    }

    @Throws(IOException::class)
    private fun getTrustStorePemFile(): File {
        if (trustStorePemFile == null) {
            val trustStorePemFile =
                File.createTempFile(TRUST_STORE_PREFIX, KeyStoreFileType.PEM.defaultFileExtension, tempDir)
            trustStorePemFile.deleteOnExit()
            trustStorePemFile.writeText(
                text = X509Helper.pemEncodeX509Certificate(trustStoreCertificate),
                charset = StandardCharsets.US_ASCII
            )
            this.trustStorePemFile = trustStorePemFile
        }
        return trustStorePemFile!!
    }

    @Throws(IOException::class)
    private fun getTrustStorePkcs12File(): File {
        if (trustStorePkcs12File == null) {
            val trustStorePkcs12File =
                File.createTempFile(TRUST_STORE_PREFIX, KeyStoreFileType.PKCS12.defaultFileExtension, tempDir)
            trustStorePkcs12File.deleteOnExit()
            FileOutputStream(trustStorePkcs12File).use { trustStoreOutputStream ->
                val bytes = X509Helper.certToPKCS12TrustStoreBytes(trustStoreCertificate, trustStorePassword)
                trustStoreOutputStream.write(bytes)
                trustStoreOutputStream.flush()
            }
            this.trustStorePkcs12File = trustStorePkcs12File
        }
        return trustStorePkcs12File!!
    }

    @Throws(IOException::class)
    private fun getTrustStoreBcfksFile(): File {
        if (trustStoreBcfksFile == null) {
            val trustStoreBcfksFile = File.createTempFile(
                TRUST_STORE_PREFIX, KeyStoreFileType.BCFKS.defaultFileExtension, tempDir
            )
            trustStoreBcfksFile.deleteOnExit()
            FileOutputStream(trustStoreBcfksFile).use { trustStoreOutputStream ->
                val bytes = X509Helper.certToBCFKSTrustStoreBytes(trustStoreCertificate, trustStorePassword)
                trustStoreOutputStream.write(bytes)
                trustStoreOutputStream.flush()
            }
            this.trustStoreBcfksFile = trustStoreBcfksFile
        }
        return trustStoreBcfksFile!!
    }

    fun getKeyStoreKeyType(): X509KeyType {
        return keyStoreKeyType
    }

    fun getKeyStoreKeyPair(): KeyPair {
        return keyStoreKeyPair
    }

    fun getKeyStoreCertExpirationMillis(): Long {
        return keyStoreCertExpirationMillis
    }

    fun getKeyStoreCertificate(): X509Certificate {
        return keyStoreCertificate
    }

    fun getKeyStorePassword(): String {
        return keyStorePassword
    }

    fun isKeyStoreEncrypted(): Boolean {
        return keyStorePassword.isNotEmpty()
    }

    /**
     * Returns the path to the key store file in the given format (JKS, PEM, ...). Note that the file is created lazily,
     * the first time this method is called. The key store file is temporary and will be deleted on exit.
     * @param storeFileType the store file type (JKS, PEM, ...).
     * @return the path to the key store file.
     * @throws IOException if there is an error creating the key store file.
     */
    @Throws(IOException::class)
    fun getKeyStoreFile(storeFileType: KeyStoreFileType): File {
        return when (storeFileType) {
            KeyStoreFileType.JKS -> getKeyStoreJksFile()
            KeyStoreFileType.PEM -> getKeyStorePemFile()
            KeyStoreFileType.PKCS12 -> getKeyStorePkcs12File()
            KeyStoreFileType.BCFKS -> getKeyStoreBcfksFile()
            else -> throw IllegalArgumentException(
                "Invalid key store type: $storeFileType, must be one of: ${
                    Arrays.toString(
                        KeyStoreFileType.values()
                    )
                }"
            )
        }
    }

    @Throws(IOException::class)
    private fun getKeyStoreJksFile(): File {
        if (keyStoreJksFile == null) {
            val keyStoreJksFile =
                File.createTempFile(KEY_STORE_PREFIX, KeyStoreFileType.JKS.defaultFileExtension, tempDir)
            keyStoreJksFile.deleteOnExit()
            FileOutputStream(keyStoreJksFile).use { keyStoreOutputStream ->
                val bytes = X509Helper.certAndPrivateKeyToJavaKeyStoreBytes(
                    keyStoreCertificate,
                    keyStoreKeyPair.private,
                    keyStorePassword
                )
                keyStoreOutputStream.write(bytes)
                keyStoreOutputStream.flush()
            }
            this.keyStoreJksFile = keyStoreJksFile
        }
        return keyStoreJksFile!!
    }

    @Throws(IOException::class)
    private fun getKeyStorePemFile(): File {
        if (keyStorePemFile == null) {
            val keyStorePemFile =
                File.createTempFile(KEY_STORE_PREFIX, KeyStoreFileType.PEM.defaultFileExtension, tempDir)
            keyStorePemFile.deleteOnExit()
            keyStorePemFile.writeText(
                text = X509Helper.pemEncodeCertAndPrivateKey(
                    keyStoreCertificate,
                    keyStoreKeyPair.private,
                    keyStorePassword
                ), charset = StandardCharsets.US_ASCII
            )
            this.keyStorePemFile = keyStorePemFile
        }
        return keyStorePemFile!!
    }

    @Throws(IOException::class)
    private fun getKeyStorePkcs12File(): File {
        if (keyStorePkcs12File == null) {
            val keyStorePkcs12File =
                File.createTempFile(KEY_STORE_PREFIX, KeyStoreFileType.PKCS12.defaultFileExtension, tempDir)
            keyStorePkcs12File.deleteOnExit()
            FileOutputStream(keyStorePkcs12File).use { keyStoreOutputStream ->
                val bytes = X509Helper.certAndPrivateKeyToPKCS12Bytes(
                    keyStoreCertificate,
                    keyStoreKeyPair.private,
                    keyStorePassword
                )
                keyStoreOutputStream.write(bytes)
                keyStoreOutputStream.flush()
            }
            this.keyStorePkcs12File = keyStorePkcs12File
        }
        return keyStorePkcs12File!!
    }

    @Throws(IOException::class)
    private fun getKeyStoreBcfksFile(): File {
        if (keyStoreBcfksFile == null) {
            val keyStoreBcfksFile = File.createTempFile(
                KEY_STORE_PREFIX, KeyStoreFileType.BCFKS.defaultFileExtension, tempDir
            )
            keyStoreBcfksFile.deleteOnExit()
            FileOutputStream(keyStoreBcfksFile).use { keyStoreOutputStream ->
                val bytes = X509Helper.certAndPrivateKeyToBCFKSBytes(
                    keyStoreCertificate, keyStoreKeyPair.private, keyStorePassword
                )
                keyStoreOutputStream.write(bytes)
                keyStoreOutputStream.flush()
            }
            this.keyStoreBcfksFile = keyStoreBcfksFile
        }
        return keyStoreBcfksFile!!
    }

    /**
     * Sets the SSL system properties such that the given X509Util object can be used to create SSL Contexts that
     * will use the trust store and key store files created by this test context. Example usage:
     * <pre>
     *     X509TestContext testContext = ...; // create the test context
     *     X509Util x509Util = new QuorumX509Util();
     *     testContext.setSystemProperties(x509Util, KeyStoreFileType.JKS, KeyStoreFileType.JKS);
     *     // The returned context will use the key store and trust store created by the test context.
     *     SSLContext ctx = x509Util.getDefaultSSLContext();
     * </pre>
     * @param x509Util the X509Util.
     * @param keyStoreFileType the store file type to use for the key store (JKS, PEM, ...).
     * @param trustStoreFileType the store file type to use for the trust store (JKS, PEM, ...).
     * @throws IOException if there is an error creating the key store file or trust store file.
     */
    @Throws(IOException::class)
    fun setSystemProperties(
        x509Util: X509Util,
        keyStoreFileType: KeyStoreFileType,
        trustStoreFileType: KeyStoreFileType
    ) {
        System.setProperty(x509Util.sslKeystoreLocationProperty, this.getKeyStoreFile(keyStoreFileType).absolutePath)
        System.setProperty(x509Util.sslKeystorePasswdProperty, this.getKeyStorePassword())
        System.setProperty(x509Util.sslKeystoreTypeProperty, keyStoreFileType.propertyValue)
        System.setProperty(
            x509Util.sslTruststoreLocationProperty,
            this.getTrustStoreFile(trustStoreFileType).absolutePath
        )
        System.setProperty(x509Util.sslTruststorePasswdProperty, this.getTrustStorePassword())
        System.setProperty(x509Util.sslTruststoreTypeProperty, trustStoreFileType.propertyValue)
        hostnameVerification?.let {
            System.setProperty(x509Util.sslHostnameVerificationEnabledProperty, it.toString())
        } ?: System.clearProperty(x509Util.sslHostnameVerificationEnabledProperty)
    }

    /**
     * Clears system properties set by
     * {@link #setSystemProperties(X509Util, KeyStoreFileType, KeyStoreFileType)}.
     * @param x509Util the X509Util to read property keys from.
     */
    fun clearSystemProperties(x509Util: X509Util) {
        System.clearProperty(x509Util.sslKeystoreLocationProperty)
        System.clearProperty(x509Util.sslKeystorePasswdProperty)
        System.clearProperty(x509Util.sslKeystorePasswdPathProperty)
        System.clearProperty(x509Util.sslKeystoreTypeProperty)
        System.clearProperty(x509Util.sslTruststoreLocationProperty)
        System.clearProperty(x509Util.sslTruststorePasswdProperty)
        System.clearProperty(x509Util.sslTruststorePasswdPathProperty)
        System.clearProperty(x509Util.sslTruststoreTypeProperty)
        System.clearProperty(x509Util.sslHostnameVerificationEnabledProperty)
    }

}

