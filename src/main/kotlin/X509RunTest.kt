import common.*
import util.BouncyCastle
import util.toKeyPair
import x509.X509Context
import x509.X509Helper
import java.io.File
import java.security.KeyStore

class X509RunTest {

    private val x509Context = initX509()
    private fun initX509(): X509Context {
        val tempDir = File("/Users/hieplq1.rpm/KotlinProjects/CATest")
//        val trustStoreKeyPair = X509Helper.generateRSAKeyPair()
        val trustStoreKeyPair = X509Helper.generateECKeyPair()
//        val trustStoreKeyPair = BouncyCastle.getInstance().genECKeyPair().toKeyPair()
        val trustStoreCertExpirationMillis = System.currentTimeMillis() + 1000000

        val keyStoreCertExpirationMillis = trustStoreCertExpirationMillis + 1000000
        val hostnameVerification = false
//        val keyStoreKeyPair = X509Helper.generateRSAKeyPair()
        val keyStoreKeyPair = X509Helper.generateECKeyPair()
//        val keyStoreKeyPair = BouncyCastle.getInstance().genECKeyPair().toKeyPair()
        val x509Context = X509Context(
            tempDir = tempDir,
            trustStoreKeyPair = trustStoreKeyPair,
            trustStoreCertExpirationMillis = trustStoreCertExpirationMillis,
            trustStorePassword = trustStorePassword,
            keyStoreKeyPair = keyStoreKeyPair,
            keyStoreCertExpirationMillis = keyStoreCertExpirationMillis,
            keyStorePassword = keyStorePassword,
            hostnameVerification = hostnameVerification
        )
        return x509Context
    }

    fun run() {
        loadTrustKeyStore()
        loadKeystore()
    }

    private fun loadTrustKeyStore() {
        val JKS = x509Context.getTrustStoreFile(KeyStoreFileType.JKS)
        trustStoreJks(JKS).loadTrustStore().info()
        val PEM = x509Context.getTrustStoreFile(KeyStoreFileType.PEM)
        trustStorePem(PEM).loadTrustStore().info()
        val PKCS12 = x509Context.getTrustStoreFile(KeyStoreFileType.PKCS12)
        trustStorePkcs12(PKCS12).loadTrustStore().info()
        val BCFKS = x509Context.getTrustStoreFile(KeyStoreFileType.BCFKS)
        println("loadTrustKeyStore BCFKS $BCFKS")
        trustStoreBcfks(BCFKS).loadTrustStore().info()
    }

    private fun loadKeystore() {
        val JKS = x509Context.getKeyStoreFile(KeyStoreFileType.JKS)
        keyStoreJks(JKS).loadKeyStore().info()
        val PEM = x509Context.getKeyStoreFile(KeyStoreFileType.PEM)
        keyStorePem(PEM).loadKeyStore().info()
        val PKCS12 = x509Context.getKeyStoreFile(KeyStoreFileType.PKCS12)
        keyStoreJks(PKCS12).loadKeyStore().info()
        val BCFKS = x509Context.getKeyStoreFile(KeyStoreFileType.BCFKS)
        keyStoreBcfks(BCFKS).loadKeyStore().info()
    }

    private fun trustStorePkcs12(file: File): PKCS12FileLoader {
        return PKCS12FileLoader.Builder()
            .setTrustStorePath(file.absolutePath)
            .setTrustStorePassword(trustStorePassword)
            .build()
    }

    fun trustStorePem(file: File): PEMFileLoader {
        return PEMFileLoader.Builder()
            .setTrustStorePath(file.absolutePath)
            .setTrustStorePassword(trustStorePassword)
            .build()
    }

    fun trustStoreJks(file: File): JKSFileLoader {
        return JKSFileLoader.Builder()
            .setTrustStorePath(file.absolutePath)
            .setTrustStorePassword(trustStorePassword)
            .build()
    }

    fun trustStoreBcfks(file: File): BCFKSFileLoader {
        return BCFKSFileLoader.Builder()
            .setTrustStorePath(file.absolutePath)
            .setTrustStorePassword(trustStorePassword)
            .build()
    }
    private fun keyStorePkcs12(file: File): PKCS12FileLoader {
        return PKCS12FileLoader.Builder()
            .setKeyStorePath(file.absolutePath)
            .setKeyStorePassword(trustStorePassword)
            .build()
    }

    fun keyStorePem(file: File): PEMFileLoader {
        return PEMFileLoader.Builder()
            .setKeyStorePath(file.absolutePath)
            .setKeyStorePassword(trustStorePassword)
            .build()
    }

    fun keyStoreJks(file: File): JKSFileLoader {
        return JKSFileLoader.Builder()
            .setKeyStorePath(file.absolutePath)
            .setKeyStorePassword(trustStorePassword)
            .build()
    }

    fun keyStoreBcfks(file: File): BCFKSFileLoader {
        return BCFKSFileLoader.Builder()
            .setKeyStorePath(file.absolutePath)
            .setKeyStorePassword(trustStorePassword)
            .build()
    }
    companion object {
        const val trustStorePassword = "baka3k"
        const val keyStorePassword = "baka3k"
    }
}

fun KeyStore.info() {
    println("provider:${provider.info}")
    println("--------------------------")
    aliases().asIterator().forEach {
        val cert = getCertificate(it)
        println("cert: $cert")
    }
}