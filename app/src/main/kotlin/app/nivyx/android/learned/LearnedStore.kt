package app.nivyx.android.learned

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypted-at-rest storage for the learned-strategy cache (host *hashes* only, never names).
 * The AES-GCM key lives in the Android Keystore. If the Keystore is unavailable nothing is
 * persisted: privacy wins over convenience, the engine simply re-learns.
 */
class LearnedStore(context: Context) {
    private val file = File(context.applicationContext.noBackupFilesDir, "learned.bin")

    fun save(json: String) {
        if (Build.VERSION.SDK_INT < 23) return // no Keystore AES-GCM: persist nothing rather than store in clear
        runCatching {
            val cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key()) }
            val out = cipher.iv + cipher.doFinal(json.toByteArray())
            val tmp = File(file.parentFile, "learned.tmp")
            tmp.writeBytes(out)
            if (!tmp.renameTo(file)) {
                file.writeBytes(out)
                tmp.delete()
            }
        }.onFailure { Log.w(TAG, "could not persist learned cache: ${it.javaClass.simpleName}") }
    }

    fun load(): String? {
        if (Build.VERSION.SDK_INT < 23 || !file.exists()) return null
        return runCatching {
            val raw = file.readBytes()
            require(raw.size > IV_LEN + 16 && raw.size < MAX_BYTES)
            val cipher = Cipher.getInstance(TRANSFORM).apply {
                init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw, 0, IV_LEN))
            }
            String(cipher.doFinal(raw, IV_LEN, raw.size - IV_LEN))
        }.onFailure {
            Log.w(TAG, "discarding unreadable learned cache")
            file.delete()
        }.getOrNull()
    }

    fun clear() {
        file.delete()
    }

    @androidx.annotation.RequiresApi(23)
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    private companion object {
        const val TAG = "nivyx"
        const val ALIAS = "nivyx.learned.v1"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_LEN = 12
        const val MAX_BYTES = 1024 * 1024
    }
}
