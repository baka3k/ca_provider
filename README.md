# Getting started
**Project just only for testing**
```
 fun getX509Context(): X509Context {
        val tempDir = File("path_store_cer\\cert") // output CA
        val trustStoreKeyPair = X509Helper.generateRSAKeyPair()
        val trustStoreCertExpirationMillis = System.currentTimeMillis() + 1000000
        val trustStorePassword = "baka3k"
        val keyStorePassword = "baka3k"
        val keyStoreCertExpirationMillis = trustStoreCertExpirationMillis + 1000000
        val hostnameVerification = false
        val keyStoreKeyPair = X509Helper.generateRSAKeyPair()
        var x509Context = X509Context(
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
        val x509Context = getX509Context()
        x509Context.getTrustStoreCertificate()
        x509Context.getKeyStoreCertificate()
        x509Context.getTrustStoreFile(KeyStoreFileType.JKS)
        x509Context.getTrustStoreFile(KeyStoreFileType.PEM)
        x509Context.getTrustStoreFile(KeyStoreFileType.PKCS12)
        x509Context.getTrustStoreFile(KeyStoreFileType.BCFKS)
    }
```