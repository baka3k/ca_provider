package common

import util.PemReader
import java.io.File
import java.security.KeyStore
import java.util.*


class PEMFileLoader(keyStorePath: String, trustStorePath: String, keyStorePassword: String, trustStorePassword: String) : FileKeyStoreLoader(keyStorePath, trustStorePath,
    keyStorePassword,
    trustStorePassword
) {
    override fun loadKeyStore(): KeyStore {
        val passwordOption = if (keyStorePassword.isEmpty()) {
            Optional.empty<String>()
        } else {
            Optional.of(keyStorePassword)
        }
        val file = File(keyStorePath)
        return PemReader.loadKeyStore(file, file, passwordOption)
    }

    override fun loadTrustStore(): KeyStore {
        return PemReader.loadTrustStore(File(trustStorePath))
    }
    class Builder : FileKeyStoreLoader.Builder<PEMFileLoader>() {
        override fun build(): PEMFileLoader {
            return PEMFileLoader(keyStorePath, trustStorePath, keyStorePassword, trustStorePassword)
        }
    }
}