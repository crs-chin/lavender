/*
 * Javender.java
 * Copyright (C) 2013  Crs Chin <crs.chin@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

package com.javender;

import android.os.SystemProperties;
import android.os.RegistrantList;
import android.os.Registrant;
import android.os.Handler;
import android.os.AsyncResult;
import android.util.Log;
import android.util.EventLog;

import com.javender.VerdictReq;

/**
 * Class that provide access to lavender service, and listen to
 * levender service on network events at the save time
 * NOTICE:
 *  There's limitations on android, as permisions are verified by
 * PID, UID and executable path, if they all are the same, there's
 * no way to verdict it, and this circumstance DO exist, eg. all
 * android java services reside in the same process space and got
 * the same PID, UID and executable path, SO THERE'S NO WAY TO JUDGE
 * APPS ACCESS NETWORK BY THEIR SERVICES.
 */
public class Javender{
    private static final String LOG_TAG = "JAVENDER";

    // verdict results
    public static final int VERDICT_NONE = 0;
    public static final int VERDICT_QUERY = 1;
    public static final int VERDICT_ALLOW_ONCE = 2;
    public static final int VERDICT_ALLOW_ALWAYS = 3;
    public static final int VERDICT_DENY_ONCE = 4;
    public static final int VERDICT_DENY_ALWAYS = 5;
    public static final int VERDICT_KILL_ONCE = 6;
    public static final int VERDICT_KILL_ALWAYS = 7;

    // connection stats
    public static final int DISCONNECTED = 0;
    public static final int CONNECTED = 1;

    private static final RegistrantList mVerdictNotify = new RegistrantList();
    private static final RegistrantList mConnectNotify = new RegistrantList();
    private static final RegistrantList mMsgNotify = new RegistrantList();
    private static final Object mLock = new Object();

    public static final void registerOnVerdict(Handler h, int what, Object obj)  {
        Registrant r = new Registrant(h, what, obj);

        synchronized(mLock)  {
            mVerdictNotify.add(r);
        }
    }

    public static final void registerOnConnect(Handler h, int what, Object obj)  {
        Registrant r = new Registrant(h, what, obj);

        synchronized(mLock)  {
            mConnectNotify.add(r);
            r.notifyRegistrant(new AsyncResult(null, mConnectState, null));
        }
    }

    public static final void registerOnMsg(Handler h, int what, Object obj)  {
        Registrant r = new Registrant(h, what, obj);

        synchronized(mLock)  {
            mMsgNotify.add(r);
        }
    }

    public static class OnConnectListener{
        public void onConnect(int state, int peer)  {
            mConnectState = state;
            mPeerID = peer;
            Log.i(LOG_TAG, "onConnectListener:" + state + " " + peer);
            mConnectNotify.notifyRegistrants();
        }
    }

    public static class OnVerdictListener{
        public void onVerdict(byte[] rid, int[] pid, int[] uid, String[] exe, long time)  {
            VerdictReq req = new VerdictReq(rid, pid, uid, exe, time);
            mVerdictNotify.notifyRegistrants(new AsyncResult(null, req, null));
        }
    }

    public static class OnMsgListener{
        public void onMsg(int type, long time, byte[] msg)  {
            CactusMsg info = new CactusMsg(type, time, msg);
            mMsgNotify.notifyRegistrants(new AsyncResult(null, info, null));
        }
    }

    public static int mPeerID = 0;
    public static int mConnectState = DISCONNECTED;
    public static boolean mIsFrontEnd = false;

    // connection flags
    public static final int CONNECT_F_ABSTRACT = 1;
    public static final int CONNECT_F_FRONT_END = (1<<1);

    private static final OnConnectListener mOnConnect = new OnConnectListener();
    private static final OnVerdictListener mOnVerdict = new OnVerdictListener();
    private static final OnMsgListener mOnMsg = new OnMsgListener();

    // state vars will be setup in the callback
    public static synchronized boolean connect(String path, int flags)  {
        int peer;

        if(mConnectState == CONNECTED)
            return true;
        if(__connect(path, flags, mOnConnect, mOnVerdict, mOnMsg))  {
            if((flags & CONNECT_F_FRONT_END) != 0)
                mIsFrontEnd = true;
            return true;
        }
        return false;
    }

    // state vars will be cleared in the callback
    public static synchronized void disconnect()  {
        if(mConnectState == CONNECTED)
            __disconnect();
        mIsFrontEnd = false;
    }

    // return 0 on success, @onVerdict: non-null will self register as
    // front-end, @onMsg has no effect if not registered as front-end
    private static native boolean __connect(String path, int flags,
                                            OnConnectListener onConnect,
                                            OnVerdictListener onVerdict,
                                            OnMsgListener onMsg);
    private static native void __disconnect();

    // cactus states
    public static final int CACTUS_INACTIVE = 0;
    public static final int CACTUS_ACTIVE = 1;

    public static native int getCactusState();
    public static native boolean setCactusState(int state);

    public static native boolean sendVerdict(byte[] rid, int verd);

    public static native boolean loadRules(String path);
    public static native boolean dumpRules(String path);

    public static native String versionInfo();

    // flush all logs into persistent storage
    public static native boolean flushLogs();

    // log types
    public static final int LOG_MAIN = 0; // main log of lavender
    public static final int LOG_RTNL = 1; // system network subsystem log
    public static final int LOG_UEVENT = 2; // system uevent log
    public static final int LOG_CONNTRACK = 3; // system network fw state log

    // log levels
    public static final int LOG_DEBUG = 0;
    public static final int LOG_INFO = 1;
    public static final int LOG_WARN = 2;
    public static final int LOG_EMERG = 3;
    public static final int LOG_ERROR = 4;
    public static final int LOG_FATAL = 5;

    public static native boolean setLogTypeEnable(int type, boolean state);
    public static native boolean setLogLevelEnable(int level, boolean state);

    public static native boolean getLogTypeEnable(int type);
    public static native boolean getLogLevelEnable(int level);

    public void startup()  {
        Log.d(LOG_TAG, "notify init to start service lavender");
        SystemProperties.set("net.lavender.enable", "1");
        // restore after triger service start
        SystemProperties.set("net.lavender.enable", "0");
    }

    // Do *NOT* use brutal way to stop the service throuh init, use
    // the SIGTERM or lavender rpc
    public static native void shutdown();

    public static native boolean setCounterEnable(boolean enable);
    public static native boolean getCounterEnable();

    // cactus service availability
    public static final int CACTUS_UNAVAILABLE = 0;
    public static final int CACTUS_AVAILABLE = 1;

    public static native int checkCactusStatus();
    // TODO: more natives to be exported.

    static {
        try {
            System.loadLibrary("javender");
        } catch(Exception e)  {
            Log.e(LOG_TAG, "unable to load javender library");
        }
    }
}

