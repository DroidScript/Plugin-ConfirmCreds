package com.candlelight.confirmcredential.plugins.user;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.widget.Toast;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class DeviceCredentialHelper {
    private Context context;
    private Activity activity;
    private boolean isKeyCreated = false;

    /** Alias for our key in the Android Key Store. */
    private static final String KEY_NAME = "DS_CredentialConfirm";
    private static final byte[] SECRET_BYTE_ARRAY = new byte[] {7, 4, 1, 0, 5, 9};

    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 100;

    /**
     * If the user has unlocked the device Within the last this number of seconds,
     * it can be considered as an authenticator.
     */
    public int authenticationDurationSeconds = 30;

    private KeyguardManager mKeyguardManager;

    private OnCredentialResult onCredentialResult;

    public DeviceCredentialHelper(Context ctx) {
        this.context = ctx;
        this.activity = (Activity) ctx;
        
        mKeyguardManager = (KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE);
        
        // We can generate the key initially,
        // but it prevents us from changing the duration.
        // if(this.isKeyguardSecure()) this.createKey();
    }
    
    public boolean isKeyguardSecure() {
        return mKeyguardManager.isKeyguardSecure();
    }
    
    public void setOnCredentialResult(OnCredentialResult onCredentialResult) {
        this.onCredentialResult = onCredentialResult;
    }

    /**
     * Tries to encrypt some data with the generated key in {@link #createKey} which
     * only works if the user has just authenticated via device credentials.
     */
    public boolean tryEncrypt() {
        if (!this.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a lock screen.
            this.onCredentialResult.onConfirmed(false, "Secure lock screen hasn't set up.");
            return false;
        }
        
        if(!isKeyCreated) this.createKey();
        
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);
            Cipher cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);

            // Try encrypting something, it will only work if the user authenticated within
            // the last AUTHENTICATION_DURATION_SECONDS seconds.
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            cipher.doFinal(SECRET_BYTE_ARRAY);

            // If the user has recently authenticated, you will reach here.
            this.onCredentialResult.onConfirmed(true, "");

            // It's actually true, but if I use it correctly,
            // it works a second time when it's inside the if block.
            return false;
        } catch (UserNotAuthenticatedException e) {
            // User is not authenticated, let's authenticate with device credentials.
            showAuthenticationScreen();
            return false;
        } catch (KeyPermanentlyInvalidatedException e) {
            // This happens if the lock screen has been disabled or reset after the key was
            this.onCredentialResult.onConfirmed(false, "Keys are invalidated after created.\n" + e.getMessage());
            return false;
        } catch (BadPaddingException | IllegalBlockSizeException | KeyStoreException |
        CertificateException | UnrecoverableKeyException | IOException
        | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with device credentials within the last X seconds.
     */
    private void createKey() {
        // Generate a key to decrypt payment credentials, tokens, etc.
        // This will most likely be a registration step for the user when they are setting up your app.
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                                                              KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                              .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                              .setUserAuthenticationRequired(true)
                              // Require that the user has unlocked in the last 30 seconds
                              .setUserAuthenticationValidityDurationSeconds(authenticationDurationSeconds)
                              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                              .build());
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException
        | InvalidAlgorithmParameterException | KeyStoreException
        | CertificateException | IOException e) {
            throw new RuntimeException("Failed to create a symmetric key", e);
        }
        
        isKeyCreated = true;
    }

    private void showAuthenticationScreen() {
        // Create the Confirm Credentials screen. You can customize the title and description. Or
        // we will provide a generic one for you if you leave it null
        Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            activity.startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            // Challenge completed, proceed with using cipher
            if (resultCode == Activity.RESULT_OK) {
                if (tryEncrypt()) {
                    this.onCredentialResult.onConfirmed(true, "");
                }
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
                this.onCredentialResult.onConfirmed(false, "Authentication failed.");
            }
        }
    }
    
    public interface OnCredentialResult {
        void onConfirmed(boolean isConfirmed, String errorMessage);
    }
}

