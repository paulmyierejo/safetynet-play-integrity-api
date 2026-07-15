package com.example.integritydemo;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.safetynet.AttestationClient;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;

/**
 * SafetyNet Attestation API Integration Example
 *
 * DEPRECATED: SafetyNet Attestation API was deprecated in January 2022.
 * Migrate to Play Integrity API: https://developer.android.com/google/play/integrity
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "SafetyNetDemo";
    private static final String API_KEY = "YOUR_GOOGLE_API_KEY";
    private static final int PLAY_SERVICES_AVAILABILITY_REQUEST = 1001;

    private Button btnAttest;
    private TextView tvResult;

    private AttestationClient attestationClient;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btnAttest = findViewById(R.id.btn_attest);
        tvResult = findViewById(R.id.tv_result);

        // Get the AttestationClient
        attestationClient = SafetyNet.getClient(this);

        btnAttest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                performAttestation();
            }
        });
    }

    private void performAttestation() {
        tvResult.setText("Checking Google Play Services...");
        btnAttest.setEnabled(false);

        // Step 1: Check Google Play Services availability
        GoogleApiAvailability gpa = GoogleApiAvailability.getInstance();
        int result = gpa.isGooglePlayServicesAvailable(this);

        if (result != ConnectionResult.SUCCESS) {
            if (gpa.isUserResolvableError(result)) {
                gpa.getErrorDialog(this, result, PLAY_SERVICES_AVAILABILITY_REQUEST);
            }
            tvResult.setText("Google Play Services not available: " + result);
            btnAttest.setEnabled(true);
            return;
        }

        // Step 2: Generate nonce (must be at least 16 bytes, unique per request)
        // In production: request nonce from YOUR SERVER
        byte[] nonce = generateNonce();
        String nonceString = Base64.encodeToString(nonce, Base64.URL_SAFE | Base64.NO_WRAP);

        Log.d(TAG, "Nonce: " + nonceString);

        // Step 3: Call SafetyNet Attestation API
        attestationClient.attest(nonce, API_KEY)
                .addOnSuccessListener(this, new OnSuccessListener<SafetyNetApi.AttestationResult>() {
                    @Override
                    public void onSuccess(SafetyNetApi.AttestationResult attestationResult) {
                        // Decode and verify the JWS response
                        String jwsResult = attestationResult.getJwsResult();
                        parseAndDisplayResult(jwsResult);

                        // Step 4: Send token to YOUR SERVER for verification
                        sendToServer(jwsResult);

                        btnAttest.setEnabled(true);
                    }
                })
                .addOnFailureListener(this, new OnFailureListener() {
                    @Override
                    public void onFailure(@NonNull Exception e) {
                        Log.e(TAG, "SafetyNet Attestation failed", e);
                        tvResult.setText("Attestation failed: " + e.getMessage());
                        btnAttest.setEnabled(true);
                    }
                });
    }

    /**
     * Generate a 16+ byte nonce.
     * IMPORTANT: In production, request this from your server to prevent replay attacks.
     */
    private byte[] generateNonce() {
        try {
            // Combine random data + timestamp + request ID from server
            long timestamp = System.currentTimeMillis();
            String combined = timestamp + ":" + new Random().nextLong();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return java.util.Arrays.copyOf(
                    digest.digest(combined.getBytes(StandardCharsets.UTF_8)),
                    16  // Truncate to 16 bytes
            );
        } catch (Exception e) {
            Log.e(TAG, "Nonce generation failed", e);
            return new byte[16];  // Fallback
        }
    }

    /**
     * Parse the JWS response and display key fields.
     * IMPORTANT: Full verification (signature, nonce, package name) must be done server-side.
     */
    private void parseAndDisplayResult(String jwsResult) {
        if (jwsResult == null || jwsResult.isEmpty()) {
            tvResult.setText("Empty response from SafetyNet");
            return;
        }

        // JWS format: header.payload.signature
        String[] parts = jwsResult.split("\\.");
        if (parts.length != 3) {
            tvResult.setText("Invalid JWS format");
            return;
        }

        try {
            // Decode header and payload (Base64URL)
            String headerJson = new String(
                    Base64.decode(parts[0], Base64.URL_SAFE | Base64.NO_WRAP),
                    StandardCharsets.UTF_8
            );
            String payloadJson = new String(
                    Base64.decode(parts[1], Base64.URL_SAFE | Base64.NO_WRAP),
                    StandardCharsets.UTF_8
            );

            Log.d(TAG, "Header: " + headerJson);
            Log.d(TAG, "Payload: " + payloadJson);

            // Parse payload JSON (in production, use a JSON library)
            StringBuilder display = new StringBuilder();
            display.append("SafetyNet Response Received\n");
            display.append("─────────────────────────\n");
            display.append("JWS Header: ").append(headerJson).append("\n");
            display.append("JWS Payload: ").append(payloadJson).append("\n");
            display.append("─────────────────────────\n");
            display.append("⚠️  Client-side display only!\n");
            display.append("⚠️  Verify signature + nonce on SERVER.\n");

            // Extract key fields for display (real parsing should use JSON library)
            if (payloadJson.contains("\"basicIntegrity\"")) {
                display.append("\n→ Full verification on server is REQUIRED");
            }

            tvResult.setText(display.toString());

        } catch (Exception e) {
            Log.e(TAG, "Failed to parse JWS", e);
            tvResult.setText("Parse error: " + e.getMessage());
        }
    }

    /**
     * Send the attestation token to your backend server for verification.
     * NEVER perform security-critical verification client-side.
     */
    private void sendToServer(String jwsToken) {
        // Example using AsyncTask or Retrofit:
        // ApiService.sendAttestationToken(jwsToken, new Callback() { ... });
        Log.d(TAG, "Sending to server: " + jwsToken);
        // TODO: Implement HTTP call to your verification endpoint
    }
}
