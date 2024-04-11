package common

import java.util.*

/**
 * This enum represents the file type of a KeyStore or TrustStore.
 * Currently, JKS (Java keystore), PEM, PKCS12, and BCFKS types are supported.
 */
enum class KeyStoreFileType(
    /**
     * The file extension that is associated with this file type.
     */
    val defaultFileExtension: String
) {
    JKS(".jks"),
    PEM(".pem"),
    PKCS12(".p12"),
    BCFKS(".bcfks");

    val propertyValue: String
        /**
         * The property string that specifies that a key store or trust store
         * should use this store file type.
         */
        get() = this.name

    companion object {
        /**
         * Converts a property value to a StoreFileType enum. If the property value
         * is `null` or an empty string, returns `null`.
         * @param propertyValue the property value.
         * @return the common.KeyStoreFileType, or `null` if
         * `propertyValue` is `null` or empty.
         * @throws IllegalArgumentException if `propertyValue` is not
         * one of "JKS", "PEM", "BCFKS", "PKCS12", or empty/null.
         */
        fun fromPropertyValue(propertyValue: String?): KeyStoreFileType? {
            if (propertyValue == null || propertyValue.length == 0) {
                return null
            }
            return valueOf(propertyValue.uppercase(Locale.getDefault()))
        }

        /**
         * Detects the type of KeyStore / TrustStore file from the file extension.
         * If the file name ends with ".jks", returns `StoreFileType.JKS`.
         * If the file name ends with ".pem", returns `StoreFileType.PEM`.
         * If the file name ends with ".p12", returns `StoreFileType.PKCS12`.
         * If the file name ends with ".bckfs", returns `StoreFileType.BCKFS`.
         * Otherwise, throws an IllegalArgumentException.
         * @param filename the filename of the key store or trust store file.
         * @return a common.KeyStoreFileType.
         * @throws IllegalArgumentException if the filename does not end with
         * ".jks", ".pem", "p12" or "bcfks".
         */
        fun fromFilename(filename: String): KeyStoreFileType {
            val i = filename.lastIndexOf('.')
            if (i >= 0) {
                val extension = filename.substring(i)
                for (storeFileType in entries) {
                    if (storeFileType.defaultFileExtension == extension) {
                        return storeFileType
                    }
                }
            }
            throw IllegalArgumentException("Unable to auto-detect store file type from file name: $filename")
        }

        /**
         * If `propertyValue` is not null or empty, returns the result
         * of `common.KeyStoreFileType.fromPropertyValue(propertyValue)`. Else,
         * returns the result of `common.KeyStoreFileType.fromFileName(filename)`.
         * @param propertyValue property value describing the common.KeyStoreFileType, or
         * null/empty to auto-detect the type from the file
         * name.
         * @param filename file name of the key store file. The file extension is
         * used to auto-detect the common.KeyStoreFileType when
         * `propertyValue` is null or empty.
         * @return a common.KeyStoreFileType.
         * @throws IllegalArgumentException if `propertyValue` is not
         * one of "JKS", "PEM", "PKCS12", "BCFKS", or empty/null.
         * @throws IllegalArgumentException if `propertyValue`is empty
         * or null and the type could not be determined from the file name.
         */
        fun fromPropertyValueOrFileName(propertyValue: String?, filename: String): KeyStoreFileType? {
            var result = fromPropertyValue(propertyValue)
            if (result == null) {
                result = fromFilename(filename)
            }
            return result
        }
    }
}