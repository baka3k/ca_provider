package common

class BCFKSFileLoader(
    keyStorePath: String,
    trustStorePath: String,
    keyStorePassword: String,
    trustStorePassword: String,
) : StandardTypeFileKeyStoreLoader(
    keyStorePath,
    trustStorePath,
    keyStorePassword,
    trustStorePassword,
    SupportedStandardKeyFormat.BCFKS
) {
    class Builder : FileKeyStoreLoader.Builder<BCFKSFileLoader>() {
        override fun build(): BCFKSFileLoader {
            return BCFKSFileLoader(keyStorePath, trustStorePath, keyStorePassword, trustStorePassword)
        }
    }
}