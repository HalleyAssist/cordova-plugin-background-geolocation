package com.marianhello.bgloc.cordova.headless;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.google.gson.JsonObject;
import com.marianhello.bgloc.cordova.PluginRegistry;
import com.marianhello.bgloc.headless.AbstractTaskRunner;
import com.marianhello.bgloc.headless.Task;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class UDPTaskRunner extends AbstractTaskRunner {
    public static final String TAG = "UdpTaskRunner";

    public UDPTaskRunner() {
    }

    @Override
    public void runTask(final Task task) {
        String headlessTask = PluginRegistry.getInstance().getHeadlessTask();
        Log.i(TAG, "runTask: " + task.getName() + " " + headlessTask);

        if (headlessTask == null) {
            task.onError("Cannot run task due to task not registered");
            return;
        }
        // headlessTask (function passed to plugin from js as string)
        // task.getName(): Event name
        // task.getBundle(): location bundle
        if (task.getName().equals("activity")) {
            task.onResult("Not interested");
            return;
        }

        JSONObject properties;
        try {
            properties = new JSONObject(headlessTask);
        } catch (JSONException e) {
            Log.w(TAG, "runTask: Failed to parse properties", e);
            task.onError("Failed to parse properties");
            return;
        }

        Log.i(TAG, "runTask: Properties parsed");

        String encPayload, token;
        // encrypt data
        try {
            // get key
            String key = properties.getString("key");
            String iv = properties.getString("iv");
            // get token
            token = properties.getString("token");
            Bundle location = task.getBundle().getBundle("params");
            assert location != null;
            String data = "[[" + location.getDouble("latitude") + "," + location.getDouble("longitude") + ","
                    + location.getLong("time") + "]]";
            // encrypt [[lat,lng,time]], key, iv
            encPayload = encrypt(key, data, iv);
        } catch (Exception e) {
            Log.w(TAG, "runTask: Failed to encrypt payload", e);
            task.onError("Failed to encrypt payload");
            return;
        }

        JsonObject payload = new JsonObject();
        // package payload: { token: jwt token, data: encrypted data }
        payload.addProperty("token", token);
        payload.addProperty("data", encPayload);

        Log.i(TAG, "runTask: Payload Encrypted");

        // udp send {token, encrypted data} to mothership:8911
        try {
            String url = properties.getString("mothershipUrl");
            int port = properties.getInt("port");
            // stringify and byteify payload
            byte[] sPayload = payload.toString().getBytes();
            Thread thread = new Thread(() -> {
                DatagramSocket socket = null;
                try {
                    Log.d(TAG, "runTask: Opening Socket");
                    socket = new DatagramSocket();
                    DatagramPacket packet = new DatagramPacket(sPayload, sPayload.length, InetAddress.getByName(url),
                            port);
                    socket.send(packet);
                    Log.d(TAG, "runTask: Packet sent successfully");
                } catch (IOException e) {
                    Log.e(TAG, "runTask: Failed to send packet {}", e);
                } finally {
                    if (socket != null)
                        socket.close();
                    Log.d(TAG, "runTask: Closed Socket");
                }
            });
            thread.start();
            task.onResult("success");
        } catch (JSONException e) {
            Log.w(TAG, "runTask: Failed to send payload", e);
            task.onError("Failed to send payload");
        }
    }

    // Encryption "borrowed" from cordova-aes256

    /**
     * <p>
     * To perform the AES256 encryption
     * </p>
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256
     *                  encryption
     * @param value     A string which will be encrypted
     * @param iv        A 16 bytes string, which will used as initial vector for
     *                  AES256 encryption
     * @return AES Encrypted string
     * @throws InvalidKeySpecException, NoSuchPaddingException,
     *                                  NoSuchAlgorithmException,
     *                                  BadPaddingException,
     *                                  IllegalBlockSizeException,
     *                                  InvalidAlgorithmParameterException,
     *                                  InvalidKeyException
     */
    private String encrypt(String secureKey, String value, String iv)
            throws InvalidKeySpecException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] pbkdf2SecuredKey = generatePBKDF2(secureKey.toCharArray(),
                "hY0wTq6xwc6ni01G".getBytes(StandardCharsets.UTF_8));

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(value.getBytes());

        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    /**
     * @param password The password
     * @param salt     The salt
     * @return PBKDF2 secured key
     * @throws InvalidKeySpecException, NoSuchAlgorithmException
     * @see <a href=
     *      "https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/PBEKeySpec.html">
     *      https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/PBEKeySpec.html</a>
     */
    private static byte[] generatePBKDF2(char[] password, byte[] salt)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec keySpec = new PBEKeySpec(password, salt, 1001, 256);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey.getEncoded();
    }
}
