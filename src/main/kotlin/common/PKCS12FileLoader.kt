package common

class PKCS12FileLoader(
    keyStorePath: String,
    trustStorePath: String,
    keyStorePassword: String,
    trustStorePassword: String
) : StandardTypeFileKeyStoreLoader(
    keyStorePath,
    trustStorePath,
    keyStorePassword,
    trustStorePassword,
    SupportedStandardKeyFormat.PKCS12
) {
    class Builder : FileKeyStoreLoader.Builder<PKCS12FileLoader>() {
        override fun build(): PKCS12FileLoader {
            return PKCS12FileLoader(keyStorePath, trustStorePath, keyStorePassword, trustStorePassword)
        }
    }
}