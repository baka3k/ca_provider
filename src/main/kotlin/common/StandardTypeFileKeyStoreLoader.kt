package common

import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.KeyStoreException


abstract class StandardTypeFileKeyStoreLoader(
    keyStorePath: String,
    trustStorePath: String,
    keyStorePassword: String,
    trustStorePassword: String,
    private val format: SupportedStandardKeyFormat,
) : FileKeyStoreLoader(keyStorePath, trustStorePath, keyStorePassword, trustStorePassword) {
    @Throws(IOException::class, GeneralSecurityException::class)
    override fun loadKeyStore(): KeyStore {
        FileInputStream(File(keyStorePath)).use { inputStream ->
            val ks: KeyStore = keyStoreInstance()
            ks.load(inputStream, passwordStringToCharArray(keyStorePassword))
            return ks
        }
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    override fun loadTrustStore(): KeyStore {
        FileInputStream(File(trustStorePath)).use { inputStream ->
            val ts = keyStoreInstance()
            ts.load(inputStream, passwordStringToCharArray(trustStorePassword))
            return ts
        }
    }
    @Throws(KeyStoreException::class)
    private fun keyStoreInstance(): KeyStore {
        return KeyStore.getInstance(format.name)
    }
    private fun passwordStringToCharArray(password: String): CharArray {
        return password.toCharArray()
    }
    enum class SupportedStandardKeyFormat {
        JKS, PKCS12, BCFKS
    }
}