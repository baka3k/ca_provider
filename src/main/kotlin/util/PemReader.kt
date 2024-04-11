package util

import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.Base64.getMimeDecoder
import java.util.regex.Pattern
import java.util.regex.Pattern.CASE_INSENSITIVE
import javax.crypto.Cipher
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.EncryptedPrivateKeyInfo
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.security.auth.x500.X500Principal


object PemReader {

    @Throws(IOException::class, GeneralSecurityException::class)
    fun loadTrustStore(certificateChainFile: File): KeyStore {
        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(null, null)

        val certificateChain: List<X509Certificate> = readCertificateChain(certificateChainFile)
        for (certificate in certificateChain) {
            val principal: X500Principal = certificate.getSubjectX500Principal()
            keyStore.setCertificateEntry(principal.getName("RFC2253"), certificate)
        }
        return keyStore
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    public fun loadKeyStore(certificateChainFile: File, privateKeyFile: File, keyPassword: Optional<String>): KeyStore {
        val key: PrivateKey = loadPrivateKey(privateKeyFile, keyPassword)

        val certificateChain = readCertificateChain(certificateChainFile)
        if (certificateChain.isEmpty()) {
            throw CertificateException(
                "Certificate file does not contain any certificates: "
                        + certificateChainFile
            )
        }

        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(null, null)
        keyStore.setKeyEntry(
            "key",
            key,
            keyPassword.orElse("").toCharArray(),
            certificateChain.toTypedArray()
        )
        return keyStore
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    fun loadPrivateKey(privateKeyFile: File, keyPassword: Optional<String>): PrivateKey {
        val privateKey = String(Files.readAllBytes(privateKeyFile.toPath()), Charsets.US_ASCII)
        return loadPrivateKey(privateKey, keyPassword)
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    fun loadPrivateKey(privateKey: String, keyPassword: Optional<String>): PrivateKey {
        val matcher = PRIVATE_KEY_PATTERN.matcher(privateKey)
        if (!matcher.find()) {
            throw KeyStoreException("did not find a private key")
        }
        val encodedKey = base64Decode(matcher.group(1))

        val encodedKeySpec: PKCS8EncodedKeySpec
        if (keyPassword.isPresent) {
            val encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo(encodedKey)
            val keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.algName)
            val secretKey = keyFactory.generateSecret(PBEKeySpec(keyPassword.get().toCharArray()))

            val cipher = Cipher.getInstance(encryptedPrivateKeyInfo.algName)
            cipher.init(DECRYPT_MODE, secretKey, encryptedPrivateKeyInfo.algParameters)
            encodedKeySpec = encryptedPrivateKeyInfo.getKeySpec(cipher)
        } else {
            encodedKeySpec = PKCS8EncodedKeySpec(encodedKey)
        }

        // this code requires a key in PKCS8 format which is not the default openssl format
        // to convert to the PKCS8 format you use : openssl pkcs8 -topk8 ...
        try {
            val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")
            return keyFactory.generatePrivate(encodedKeySpec)
        } catch (ignore: InvalidKeySpecException) {
        }

        try {
            val keyFactory = KeyFactory.getInstance("EC")
            return keyFactory.generatePrivate(encodedKeySpec)
        } catch (ignore: InvalidKeySpecException) {
        }

        val keyFactory = KeyFactory.getInstance("DSA")
        return keyFactory.generatePrivate(encodedKeySpec)
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    fun readCertificateChain(certificateChainFile: File): List<X509Certificate> {
        val contents = String(Files.readAllBytes(certificateChainFile.toPath()), Charsets.US_ASCII)
        return readCertificateChain(contents)
    }

    @Throws(CertificateException::class)
    fun readCertificateChain(certificateChain: String): List<X509Certificate> {
        val matcher = CERT_PATTERN.matcher(certificateChain)
        val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        val certificates: MutableList<X509Certificate> = ArrayList()

        var start = 0
        while (matcher.find(start)) {
            val buffer: ByteArray = base64Decode(matcher.group(1))
            certificates.add(certificateFactory.generateCertificate(ByteArrayInputStream(buffer)) as X509Certificate)
            start = matcher.end()
        }

        return certificates
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    fun loadPublicKey(publicKeyFile: File): PublicKey {
        val publicKey = String(Files.readAllBytes(publicKeyFile.toPath()), Charsets.US_ASCII)
        return loadPublicKey(publicKey)
    }

    @Throws(GeneralSecurityException::class)
    fun loadPublicKey(publicKey: String): PublicKey {
        val matcher = PUBLIC_KEY_PATTERN.matcher(publicKey)
        if (!matcher.find()) {
            throw KeyStoreException("did not find a public key")
        }
        val data: String = matcher.group(1)
        val encodedKey = base64Decode(data)

        val encodedKeySpec = X509EncodedKeySpec(encodedKey)
        try {
            val keyFactory = KeyFactory.getInstance("RSA")
            return keyFactory.generatePublic(encodedKeySpec)
        } catch (ignore: InvalidKeySpecException) {
        }

        try {
            val keyFactory = KeyFactory.getInstance("EC")
            return keyFactory.generatePublic(encodedKeySpec)
        } catch (ignore: InvalidKeySpecException) {
        }

        val keyFactory = KeyFactory.getInstance("DSA")
        return keyFactory.generatePublic(encodedKeySpec)
    }

    private fun base64Decode(base64: String): ByteArray {
        return getMimeDecoder().decode(base64.toByteArray(Charsets.US_ASCII))
    }

    private val CERT_PATTERN = Pattern.compile(
        "-+BEGIN\\s+.*CERTIFICATE[^-]*-+(?:\\s|\\r|\\n)+" // Header
                + "([a-z0-9+/=\\r\\n]+)" // Base64 text
                + "-+END\\s+.*CERTIFICATE[^-]*-+",  // Footer
        CASE_INSENSITIVE
    )

    private val PRIVATE_KEY_PATTERN = Pattern.compile(
        (("-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" // Header
                + "([a-z0-9+/=\\r\\n]+)" // Base64 text
                + "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+")),  // Footer
        CASE_INSENSITIVE
    )

    private val PUBLIC_KEY_PATTERN = Pattern.compile(
        (("-+BEGIN\\s+.*PUBLIC\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" // Header
                + "([a-z0-9+/=\\r\\n]+)" // Base64 text
                + "-+END\\s+.*PUBLIC\\s+KEY[^-]*-+")),  // Footer
        CASE_INSENSITIVE
    )
}