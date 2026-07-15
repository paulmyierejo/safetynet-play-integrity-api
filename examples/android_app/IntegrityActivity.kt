package com.example.integritydemo

import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.gms.tasks.OnFailureListener
import com.google.android.gms.tasks.OnSuccessListener
import com.google.android.gms.integrity.dto.IntegrityTokenRequest
import com.google.android.gms.integrity.IntegrityManager
import com.google.android.gms.integrity.IntegrityManagerFactory
import com.google.android.gms.integrity.model.IntegrityTokenResponse
import kotlinx.coroutines.*
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Play Integrity API Integration Example (Kotlin)
 *
 * The Play Integrity API is the successor to SafetyNet Attestation.
 * It provides better detection oftampering, device emulators, and other threats.
 *
 * Add dependency: implementation 'com.google.android.gms:play-services-integrity:18.0.0'
 */
class IntegrityActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "PlayIntegrityDemo"
        private const val SERVER_URL = "https://your-server.com/api/integrity/verify"
        private const val REQUEST_NONCE_TIMEOUT_SECONDS = 5L
    }

    private lateinit var btnCheck: Button
    private lateinit var tvResult: TextView
    private lateinit var tvVerdict: TextView

    private lateinit var integrityManager: IntegrityManager
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_integrity)

        btnCheck = findViewById(R.id.btn_check_integrity)
        tvResult = findViewById(R.id.tv_integrity_result)
        tvVerdict = findViewById(R.id.tv_verdict)

        // Initialize Integrity Manager
        integrityManager = IntegrityManagerFactory.create(applicationContext)

        btnCheck.setOnClickListener { requestIntegrityToken() }
    }

    /**
     * Request an integrity token from the Play Integrity API.
     * The token is cryptographically signed by Google.
     */
    private fun requestIntegrityToken() {
        tvResult.text = "Requesting integrity token..."
        tvVerdict.text = ""
        btnCheck.isEnabled = false

        // Step 1: Generate nonce locally (or request from server)
        val nonce = generateNonce()

        // Step 2: Build the integrity token request
        val requestBuilder = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .setCloudBackupOptions(
                IntegrityTokenRequest.CloudBackupOptions.builder()
                    .setIncludeCloudBackupHash(false)
                    .build()
            )
            .setDeviceSelectionOptions(
                IntegrityTokenRequest.DeviceSelectionOptions.builder()
                    .setRequireDeviceIntegrityLevel(
                        IntegrityTokenRequest.DeviceSelectionOptions.DEVICE_INTEGRITY_LEVEL
                    )
                    .build()
            )

        val request = requestBuilder.build()

        // Step 3: Request token asynchronously
        integrityManager.requestIntegrityToken(request)
            .addOnSuccessListener { response: IntegrityTokenResponse ->
                val token = response.token()
                displayToken(token)
                verifyOnServer(token)
                btnCheck.isEnabled = true
            }
            .addOnFailureListener { e: Exception ->
                tvResult.text = "Integrity check failed: ${e.message}"
                btnCheck.isEnabled = true
                e.printStackTrace()
            }
    }

    /**
     * Generate a nonce for the integrity request.
     * In production, this MUST be generated server-side to prevent replay attacks.
     */
    private fun generateNonce(): String {
        // BAD (demo only): Local nonce generation
        // GOOD: Request nonce from your server via HTTPS
        val timestamp = System.currentTimeMillis()
        val randomPart = java.util.UUID.randomUUID().toString()
        val raw = "$timestamp:$randomPart:SERVER_SECRET"
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(raw.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_WRAP)
    }

    /**
     * Display the raw token (for debugging only).
     * Never make security decisions based on client-side token parsing.
     */
    private fun displayToken(token: String) {
        val parts = token.split(".")
        if (parts.size != 3) {
            tvResult.text = "Invalid token format"
            return
        }

        try {
            // Decode header and payload
            val headerBytes = Base64.decode(parts[0], Base64.URL_SAFE or Base64.NO_WRAP)
            val payloadBytes = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP)
            val headerJson = String(headerBytes, Charsets.UTF_8)
            val payloadJson = String(payloadBytes, Charsets.UTF_8)

            tvResult.text = buildString {
                append("Integrity Token Received\n")
                append("─".repeat(30) + "\n")
                append("Algorithm: ${JSONObject(headerJson).optString("alg")}\n")
                append("Payload (first 500 chars):\n")
                append(payloadJson.take(500))
                if (payloadJson.length > 500) append("\n... (truncated)")
                append("\n" + "─".repeat(30) + "\n")
                append("⚠️  Full verification MUST happen on YOUR SERVER")
            }
        } catch (e: Exception) {
            tvResult.text = "Token received (parse error): ${e.message}"
        }
    }

    /**
     * Send the integrity token to your server for cryptographic verification.
     * This is the ONLY safe place to make access decisions.
     */
    private fun verifyOnServer(token: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val jsonBody = JSONObject().apply {
                    put("token", token)
                    put("deviceId", android.provider.Settings.Secure.getString(
                        contentResolver,
                        android.provider.Settings.Secure.ANDROID_ID
                    ))
                }

                val requestBody = jsonBody.toString()
                    .toRequestBody("application/json".toMediaType())

                val request = Request.Builder()
                    .url(SERVER_URL)
                    .post(requestBody)
                    .addHeader("X-Api-Key", "your-api-key")
                    .build()

                client.newCall(request).execute().use { response ->
                    val body = response.body?.string() ?: "{}"
                    val json = JSONObject(body)

                    val verified = json.optBoolean("verified", false)
                    val verdict = json.optString("verdict", "UNKNOWN")

                    withContext(Dispatchers.Main) {
                        displayVerdict(verified, verdict, json)
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    tvVerdict.text = "Server verification failed: ${e.message}"
                }
            }
        }
    }

    private fun displayVerdict(verified: Boolean, verdict: String, details: JSONObject) {
        tvVerdict.text = buildString {
            append("Server Verdict\n")
            append("─".repeat(30) + "\n")
            append("Verified: ${if (verified) "✅ YES" else "❌ NO"}\n")
            append("Verdict: $verdict\n")
            append("\nDetails:\n")
            append(details.toString(2).take(300))
        }
    }
}
