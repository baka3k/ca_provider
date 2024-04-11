package common

class JKSFileLoader(
    keyStorePath: String,
    trustStorePath: String,
    keyStorePassword: String,
    trustStorePassword: String
) : StandardTypeFileKeyStoreLoader(
    keyStorePath,
    trustStorePath,
    keyStorePassword,
    trustStorePassword,
    SupportedStandardKeyFormat.JKS
) {
    class Builder : FileKeyStoreLoader.Builder<JKSFileLoader>() {
        override fun build(): JKSFileLoader {
            return JKSFileLoader(keyStorePath, trustStorePath, keyStorePassword, trustStorePassword)
        }
    }
}