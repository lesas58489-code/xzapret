package com.xzap.client

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM encryption compatible with Python XZAPCrypto.
 * Wire format: [12B nonce][ciphertext + 16B tag]
 */
class XzapCrypto(private val key: ByteArray) {

    companion object {
        const val NONCE_SIZE = 12
        const val TAG_BITS = 128
    }

    private val random = SecureRandom()
    private val keySpec = SecretKeySpec(key, "AES")

    fun encrypt(plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(TAG_BITS, nonce))
        val ct = cipher.doFinal(plaintext)
        return nonce + ct
    }

    fun decrypt(data: ByteArray): ByteArray {
        require(data.size > NONCE_SIZE) { "Ciphertext too short" }
        val nonce = data.copyOfRange(0, NONCE_SIZE)
        val ct = data.copyOfRange(NONCE_SIZE, data.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(TAG_BITS, nonce))
        return cipher.doFinal(ct)
    }
}
