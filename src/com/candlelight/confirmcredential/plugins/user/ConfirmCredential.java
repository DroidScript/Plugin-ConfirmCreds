
/*
 DroidScript Plugin class.
 (This is where you put your plugin code)
 */

package com.candlelight.confirmcredential.plugins.user;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import java.lang.reflect.Method;

public class ConfirmCredential {
	public static String TAG = "ConfirmCredential";	
	public static float VERSION = 1.0f;	
	private Method m_callscript;
	private Object m_parent;
	private Context m_ctx;

    private DeviceCredentialHelper deviceCredentialHelper;
    private String callback;

	//Contruct plugin.
	public ConfirmCredential() {
		Log.d(TAG, "Creating plugin object");
	}

	//Initialise plugin.
	public void Init(Context ctx, Object parent) {
		try {
			Log.d(TAG, "Initialising plugin object");
			m_ctx = ctx;
			m_parent = parent;
			m_callscript = parent.getClass().getMethod("CallScript", Bundle.class);

			//Your initialisation code goes here.
			deviceCredentialHelper = new DeviceCredentialHelper(m_ctx);
            deviceCredentialHelper.setOnCredentialResult(new OnCredentialResult());
        } catch (Exception e) {
            Log.e(TAG, "Failed to Initialise plugin!", e);
        }
	}

    public void OnActivityResult(int requestCode, int resultCode, Intent data) {
        deviceCredentialHelper.onActivityResult(requestCode, resultCode, data);
    }

	//Release plugin resources.
	public void Release() {
		//Your tidy up code goes here.
		//...
	}

	//Use this method to call a function in the user's script.
	private void CallScript(Bundle b) {
		try {
			m_callscript.invoke(m_parent, b);
		} catch (Exception e) {
			Log.e(TAG, "Failed to call script function!", e);
		}
	}

	//Handle commands from DroidScript.
	public String CallPlugin(Bundle b) {
		//Extract command.
		String cmd = b.getString("cmd");

		//Process commands.
		String ret = null;
		try {

            if (cmd.equals("isScreenLockActive")) {
                return Boolean.toString(deviceCredentialHelper.isKeyguardSecure());
            } else if (cmd.equals("showAuthScreen")) {
                callback = b.getString("p1");
                deviceCredentialHelper.authenticationDurationSeconds = (int)b.getFloat("p2");
                
                deviceCredentialHelper.tryEncrypt();
			} else {
				return Float.toString(VERSION);
            }
            
		} catch (Exception e) {
            Log.e(TAG, "Plugin command failed!", e);
		}
		return ret;
	}

    private class OnCredentialResult implements DeviceCredentialHelper.OnCredentialResult {

        @Override
        public void onConfirmed(boolean isConfirmed, String errorMessage) {
            Bundle bundle = new Bundle();
            bundle.putString("cmd", callback);
            bundle.putBoolean("p1", isConfirmed);
            bundle.putString("p2", errorMessage);
            CallScript(bundle);
        }
        
    }
}


