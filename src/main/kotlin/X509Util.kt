import java.io.Closeable
import java.security.NoSuchAlgorithmException
import javax.net.ssl.SSLContext


abstract class X509Util : Closeable, AutoCloseable {

    companion object {
        private const val REJECT_CLIENT_RENEGOTIATION_PROPERTY = "jdk.tls.rejectClientInitiatedRenegotiation"
        private const val FIPS_MODE_PROPERTY = "zookeeper.fips-mode"
        const val TLS_1_1 = "TLSv1.1"
        const val TLS_1_2 = "TLSv1.2"
        const val TLS_1_3 = "TLSv1.3"

        init {
            // Client-initiated renegotiation in TLS is unsafe and
            // allows MITM attacks, so we should disable it unless
            // it was explicitly enabled by the user.
            // A brief summary of the issue can be found at
            // https://www.ietf.org/proceedings/76/slides/tls-7.pdf
            if (System.getProperty(REJECT_CLIENT_RENEGOTIATION_PROPERTY) == null) {
                println("Setting -D {}=true to disable client-initiated TLS renegotiation $REJECT_CLIENT_RENEGOTIATION_PROPERTY")
                System.setProperty(REJECT_CLIENT_RENEGOTIATION_PROPERTY, true.toString())
            }
        }

        val DEFAULT_PROTOCOL = defaultTlsProtocol()

        private fun defaultTlsProtocol(): String {
            var defaultProtocol = TLS_1_2
            val supported = SSLContext.getDefault().supportedSSLParameters.protocols
            try {
                if (supported.contains(TLS_1_3)) {
                    defaultProtocol = TLS_1_3
                }
            } catch (e: NoSuchAlgorithmException) {
                // Ignore.
            }
            println("Default TLS protocol is {$defaultProtocol}, supported TLS protocols are {$supported}")
            return defaultProtocol
        }
    }

    // ChaCha20 was introduced in OpenJDK 11.0.15 and it is not supported by JDK8.
    private fun getTLSv13Ciphers(): Array<String> {
        return arrayOf("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256")
    }

    private fun getGCMCiphers(): Array<String> {
        return arrayOf(
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        )
    }

    private fun getCBCCiphers(): Array<String> {
        return arrayOf(
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
        )
    }

    private val sslProtocolProperty: String = getConfigPrefix() + "protocol"
    private val sslEnabledProtocolsProperty: String = getConfigPrefix() + "enabledProtocols"
    private val cipherSuitesProperty: String = getConfigPrefix() + "ciphersuites"
    internal val sslKeystoreLocationProperty: String = getConfigPrefix() + "keyStore.location"
    internal val sslKeystorePasswdProperty: String = getConfigPrefix() + "keyStore.password"
    internal val sslKeystorePasswdPathProperty: String = getConfigPrefix() + "keyStore.passwordPath"
    internal val sslKeystoreTypeProperty: String = getConfigPrefix() + "keyStore.type"
    internal val sslTruststoreLocationProperty: String = getConfigPrefix() + "trustStore.location"
    internal val sslTruststorePasswdProperty: String = getConfigPrefix() + "trustStore.password"
    internal val sslTruststorePasswdPathProperty: String = getConfigPrefix() + "trustStore.passwordPath"
    internal val sslTruststoreTypeProperty: String = getConfigPrefix() + "trustStore.type"
    internal val sslContextSupplierClassProperty: String = getConfigPrefix() + "context.supplier.class"
    internal val sslHostnameVerificationEnabledProperty: String = getConfigPrefix() + "hostnameVerification"
    internal val sslCrlEnabledProperty: String = getConfigPrefix() + "crl"
    internal val sslOcspEnabledProperty: String = getConfigPrefix() + "ocsp"
    internal val sslClientAuthProperty: String = getConfigPrefix() + "clientAuth"
    internal val sslHandshakeDetectionTimeoutMillisProperty: String =
        getConfigPrefix() + "handshakeDetectionTimeoutMillis"

    protected abstract fun getConfigPrefix(): String?
}
