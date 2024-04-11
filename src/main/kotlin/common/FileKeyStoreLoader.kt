package common

abstract class FileKeyStoreLoader(
    protected val keyStorePath: String,
    val trustStorePath: String,
    protected val keyStorePassword: String,
    protected val trustStorePassword: String,
) : KeyStoreLoader {

    /**
     * Base class for builder pattern used by subclasses.
     * @param <T> the subtype of FileKeyStoreLoader created by the Builder.
    </T> */
    abstract class Builder<T : FileKeyStoreLoader> internal constructor() {
        var keyStorePath: String = ""
        var trustStorePath: String = ""
        var keyStorePassword = ""
        var trustStorePassword = ""

        fun setKeyStorePath(keyStorePath: String): Builder<T> {
            this.keyStorePath = keyStorePath
            return this
        }

        fun setTrustStorePath(trustStorePath: String): Builder<T> {
            this.trustStorePath = trustStorePath
            return this
        }

        fun setKeyStorePassword(keyStorePassword: String): Builder<T> {
            this.keyStorePassword = keyStorePassword
            return this
        }

        fun setTrustStorePassword(trustStorePassword: String): Builder<T> {
            this.trustStorePassword = trustStorePassword
            return this
        }

        abstract fun build(): T
    }

}