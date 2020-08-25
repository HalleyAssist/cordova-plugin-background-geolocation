package com.marianhello.bgloc.cordova.headless;

import android.content.Context;

import com.marianhello.bgloc.cordova.PluginRegistry;
import com.marianhello.bgloc.headless.AbstractTaskRunner;
import com.marianhello.bgloc.headless.Task;

public class UDPTaskRunner extends AbstractTaskRunner {
    // private udp
    public static String BUNDLE_KEY = "UDPTR";

    public UDPTaskRunner() {
    }

    @Override
    public void runTask(final Task task) {
        String headlessTask = PluginRegistry.getInstance().getHeadlessTask();

        if (headlessTask == null) {
            task.onError("Cannot run task due to task not registered");
            return;
        }

        // headlessTask (function passed to plugin from js as string)
        // task.getName(): Event name
        // task.getString(): json stringified location object
        //
        // if name != location return task.onResult('not interested')
        // get key
        // get token
        // encrypt [[lat,lng,time]], key, iv
        // udp socket open
        // udp send {token, encrypted data} to mothership:8911
        // udp socket close
        // task.onResult('success')
        // catch task.onError('error')

    }

    @Override
    public void setContext(Context context) {
        super.setContext(context);
        // create udp socket
    }
}
