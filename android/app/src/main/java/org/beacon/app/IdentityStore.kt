package org.beacon.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.beacon.mobile.Mobile

/**
 * Keeps the device identity (Go's marshaled private keys) encrypted at rest
 * under an AES-GCM key that never leaves the Android Keystore.
 */
class IdentityStore(context: Context) {
    private val file = File(context.noBackupFilesDir, "identity.bin")
    private val prefs = context.getSharedPreferences("beacon", Context.MODE_PRIVATE)

    var nickname: String?
        get() = prefs.getString("nickname", null)
        set(value) = prefs.edit().putString("nickname", value).apply()

    /** Returns the identity, creating and storing one on first use. */
    fun loadOrCreate(): ByteArray {
        if (file.exists()) return decrypt(file.readBytes())
        val identity = Mobile.newIdentity()
        file.writeBytes(encrypt(identity))
        return identity
    }

    /** Deletes the stored identity and its Keystore key. Irreversible. */
    fun wipe() {
        if (file.exists()) {
            file.writeBytes(ByteArray(file.length().toInt())) // overwrite before deleting
            file.delete()
        }
        keyStore().deleteEntry(ALIAS)
        prefs.edit().clear().apply()
    }

    private fun keyStore() = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun key(): SecretKey {
        (keyStore().getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    private fun encrypt(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, key()) // the Keystore picks a random IV
        return c.iv + c.doFinal(plain)
    }

    private fun decrypt(blob: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, IV_SIZE))
        return c.doFinal(blob, IV_SIZE, blob.size - IV_SIZE)
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val ALIAS = "beacon-identity"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_SIZE = 12
    }
}
