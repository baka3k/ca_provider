package common
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
interface KeyStoreLoader {
    /**
     * Loads a KeyStore which contains at least one private key and the
     * associated X509 cert chain.
     *
     * @return a new KeyStore
     * @throws IOException if loading the key store fails due to an IO error,
     * such as "file not found".
     * @throws GeneralSecurityException if loading the key store fails due to
     * a security error, such as "unsupported crypto algorithm".
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun loadKeyStore(): KeyStore

    /**
     * Loads a KeyStore which contains at least one X509 cert chain for a
     * trusted Certificate Authority (CA).
     *
     * @return a new KeyStore
     * @throws IOException if loading the trust store fails due to an IO error,
     * such as "file not found".
     * @throws GeneralSecurityException if loading the trust store fails due to
     * a security error, such as "unsupported crypto algorithm".
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun loadTrustStore(): KeyStore
}