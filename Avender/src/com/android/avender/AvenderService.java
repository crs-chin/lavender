/*
 * AvenderService.java
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
package com.android.avender;

import android.app.Service;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Notification;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.BroadcastReceiver;
import android.content.SharedPreferences;
import android.os.AsyncResult;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.FileObserver;
import android.os.RemoteException;
import android.widget.Toast;
import android.util.Log;
import android.util.EventLog;

import com.android.avender.IAvenderService;
import com.android.avender.VerdictRequest;
import com.android.avender.VerdictInfo;
import com.javender.Javender;
import com.javender.VerdictReq;
import com.javender.CactusMsg;

public class AvenderService extends Service {

    private static final String LOG_TAG = "AvenderService";
    private static final boolean DBG = true;

    private static final Javender mJavender = new Javender();
    private LavenderClient mLavender = null;
    private LavenderState mStateObs = null;
    private Context mContext = null;
    private VerdictInfo mVerdictInfo = null;

    private KeyguardManager mKG = null;
    private NotificationManager mNM = null;
    private final int NOTIFICATION_ACTIVE = 19870817;
    private final int NOTIFICATION_VERDICT = 19871127;

    private SharedPreferences mSettings = null;
    private int mCactusState = Javender.CACTUS_INACTIVE;
    private boolean mMainLogEnable = true;
    private boolean mRTNLLogEnable = false;
    private boolean mUEventLogEnable = false;
    private boolean mCONNTRACKLogEnable = false;

    private class LavenderState extends FileObserver{
        public String mPath;

        public LavenderState(String path) {
            super(path, FileObserver.CLOSE_WRITE);
            mPath = path + "lavender.stat";
        }

        @Override
        public void onEvent(int event, String path) {
            if (path == null || ! path.equals("lavender.stat"))  {
                return;
            }

            Log.i(LOG_TAG, "Lavender state file changed, checking " + path);
            if(mJavender.mConnectState != Javender.CONNECTED)  {
                // 这煞笔java，就读个字符串这么费事还读不好，煞笔到家了
                if(Javender.checkCactusStatus() == Javender.CACTUS_AVAILABLE)  {
                    Log.i(LOG_TAG, "Cactus service became available, try to connect");
                    if(! mJavender.connect(null, Javender.CONNECT_F_FRONT_END))  {
                        Log.e(LOG_TAG, "Fail to init connection to Lavender service");
                    }else   {
                        applySettings();
                    }
                }
            }
        }
    }

    private class LavenderClient extends Handler{
        private static final int EVENT_ON_CONNECT = 1;
        private static final int EVENT_ON_VERDICT = 2;
        private static final int EVENT_ON_MSG = 3;
        
        LavenderClient(Javender j)  {
            j.registerOnConnect(this, EVENT_ON_CONNECT, null);
            j.registerOnVerdict(this, EVENT_ON_VERDICT, null);
            j.registerOnMsg(this, EVENT_ON_MSG, null);
        }

        public void handleMessage (Message msg) {
            AsyncResult ar = (AsyncResult)msg.obj;
            
            switch(msg.what)  {
            case EVENT_ON_CONNECT:
                Log.i(LOG_TAG, "Lavender connection state change:" + mJavender.mConnectState);
                onConnect();
                break;
            case EVENT_ON_VERDICT:
                onVerdict((VerdictReq)ar.result);
                break;
            case EVENT_ON_MSG:
                onMsg((CactusMsg)ar.result);
                break;
            default:
                Log.e(LOG_TAG, "Unrecognized event received:" + msg.what);
                break;
            }
        }

        private void onConnect()  {
            Intent intent = new Intent("android.intent.action.LavenderStateChange");

            if(mJavender.mConnectState != Javender.CONNECTED)  {
                hideNoti();
            }
            mContext.sendOrderedBroadcast(intent, null);
        }

        private void onVerdict(VerdictReq req)  {
            mVerdictInfo = new VerdictInfo(req);

            Log.i(LOG_TAG, "Verdict request received:" + req.pid + " " + req.uid + " " + req.time);
            if(mKG.inKeyguardRestrictedInputMode())  {
                notiVerdict();
            }else  {
                Intent i = new Intent(getApplicationContext(), VerdictRequest.class);

                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                mNM.cancel(NOTIFICATION_VERDICT);
                startActivity(i);
            }
        }

        private void onMsg(CactusMsg msg)  {
            switch(msg.type)  {
            case CactusMsg.MSG_INFO:
                try {
                    String text = new String(msg.msg, "UTF-8");
                    showText(text);
                } catch (java.io.UnsupportedEncodingException e)  {
                    Log.w(LOG_TAG, "unsupported encoding showing verd info");
                }
                break;
            default:
                Log.w(LOG_TAG, "Unrecognized cactus msg:" + msg.type + ", ignored");
                break;
            }
        }
    }

    private void notiVerdict()  {
        CharSequence text = getText(R.string.verdict);
        Notification noti = new Notification(R.drawable.verdict, text, System.currentTimeMillis());
        PendingIntent contentIntent = PendingIntent.getActivity(this, 0,
                                                                new Intent(this, VerdictRequest.class), 0);
        noti.setLatestEventInfo(this, getText(R.string.verdict), text, contentIntent);
        noti.defaults = Notification.DEFAULT_SOUND | Notification.DEFAULT_VIBRATE;
        noti.flags |= Notification.FLAG_NO_CLEAR;
        mNM.notify(NOTIFICATION_VERDICT, noti);
    }

    private void showNoti()  {
        CharSequence text = getText(R.string.cactus_enabled);
        Notification noti = new Notification(R.drawable.ic_launcher, text, System.currentTimeMillis());
        PendingIntent contentIntent = PendingIntent.getActivity(this, 0,
                                                                new Intent(this, MainActivity.class), 0);
        noti.setLatestEventInfo(this, getText(R.string.cactus_enabled), text, contentIntent);
        noti.flags |= Notification.FLAG_NO_CLEAR;
        mNM.notify(NOTIFICATION_ACTIVE, noti);
    }

    private void hideNoti()  {
        mNM.cancel(NOTIFICATION_ACTIVE);
    }

    private void loadSettings()  {
        mCactusState = mSettings.getInt("cactus_state", Javender.CACTUS_INACTIVE);
        mMainLogEnable = mSettings.getBoolean("main_log", true);
        mRTNLLogEnable = mSettings.getBoolean("rtnl_log", false);
        mUEventLogEnable = mSettings.getBoolean("uevent_log", false);
        mCONNTRACKLogEnable = mSettings.getBoolean("conntrack_log", false);
    }

    private void applySettings()  {
        mJavender.setCactusState(mCactusState);
        if(mCactusState == Javender.CACTUS_ACTIVE)  {
            showNoti();
        }else  {
            hideNoti();
        }

        mJavender.setLogTypeEnable(Javender.LOG_MAIN, mMainLogEnable);
        mJavender.setLogTypeEnable(Javender.LOG_RTNL, mRTNLLogEnable);
        mJavender.setLogTypeEnable(Javender.LOG_UEVENT, mUEventLogEnable);
        mJavender.setLogTypeEnable(Javender.LOG_CONNTRACK, mCONNTRACKLogEnable);
    }

    private void saveSettings()  {
        mSettings.edit()
            .putInt("cactus_state", mCactusState)
            .putBoolean("main_log", mMainLogEnable)
            .putBoolean("rtnl_log", mRTNLLogEnable)
            .putBoolean("uevent_log", mUEventLogEnable)
            .putBoolean("conntrack_log", mCONNTRACKLogEnable)
            .commit();
    }

    private void showText(String text)  {
        Toast.makeText(getApplicationContext(), text, Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onCreate()  {
        Log.i(LOG_TAG, "creating AvenderService");

        super.onCreate();
        mContext = getBaseContext();
        if(mJavender == null)  {
            Log.e(LOG_TAG, "Javender the client library can't be initalized, abort!");
            super.stopSelf();
            return;
        }

        mSettings = getSharedPreferences("lavender-config", 0);
        loadSettings();

        mLavender = new LavenderClient(mJavender);
        mStateObs = new LavenderState("/data/lavender/");

        if(mJavender.mConnectState != Javender.CONNECTED)  {
            Log.i(LOG_TAG, "connecting to Lavender service");
            if(! mJavender.connect(null, Javender.CONNECT_F_FRONT_END))
                Log.e(LOG_TAG, "Fail to init connection to Lavender service");
        }
        mStateObs.startWatching();
        mNM = (NotificationManager)getSystemService(Context.NOTIFICATION_SERVICE);
        mKG = (KeyguardManager)getSystemService(Context.KEYGUARD_SERVICE);

        applySettings();

        showText("Avender Service active");
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    private final IAvenderService.Stub binder = new IAvenderService.Stub() {

            @Override
            public boolean connect() throws RemoteException  {
                return mJavender.connect(null, Javender.CONNECT_F_ABSTRACT | Javender.CONNECT_F_FRONT_END);
            }
        
            @Override
            public boolean getConnectState() throws RemoteException  {
                return mJavender.mConnectState == Javender.CONNECTED;
            }

            @Override
            public VerdictInfo getVerdict()  {
                return mVerdictInfo;
            }

            @Override
            public boolean setVerdict(byte[] rid, int verd)  {
                return mJavender.sendVerdict(rid, verd);
            }

            @Override
            public boolean setLogTypeEnable(int type, boolean stat)  {
                boolean ret = mJavender.setLogTypeEnable(type, stat);

                if(ret)  {
                    switch(type)  {
                    case Javender.LOG_MAIN:
                        mMainLogEnable = stat;
                        break;
                    case Javender.LOG_RTNL:
                        mRTNLLogEnable = stat;
                        break;
                    case Javender.LOG_UEVENT:
                        mUEventLogEnable = stat;
                        break;
                    case Javender.LOG_CONNTRACK:
                        mCONNTRACKLogEnable = stat;
                        break;
                    default:
                        break;
                    }
                    saveSettings();
                }
                return ret;
            }

            @Override
            public boolean getLogTypeEnable(int type)  {
                return mJavender.getLogTypeEnable(type);
            }

            @Override
            public boolean setLogLevelEnable(int level, boolean stat)  {
                return mJavender.setLogLevelEnable(level, stat);
            }

            @Override
            public boolean getLogLevelEnable(int level)  {
                return mJavender.getLogLevelEnable(level);
            }

            @Override
            public boolean getCactusState() throws RemoteException  {
                return mJavender.getCactusState() == Javender.CACTUS_ACTIVE;
            }

            @Override
            public boolean setCactusState(boolean st) throws RemoteException  {
                int stat = st ? Javender.CACTUS_ACTIVE : Javender.CACTUS_INACTIVE;
                boolean ret = mJavender.setCactusState(stat);

                if(ret)  {
                    if(mCactusState != stat)  {
                        mCactusState = stat;
                        if(mCactusState == Javender.CACTUS_ACTIVE)  {
                            showNoti();
                        }else  {
                            hideNoti();
                        }
                    }
                    saveSettings();
                }
                return ret;
            }

            @Override
            public void startLavender() throws RemoteException {
                mJavender.startup();
            }

            @Override
            public void stopLavender() throws RemoteException {
                mJavender.shutdown();   
            }

            @Override
            public String versionInfo() throws RemoteException {
                return mJavender.versionInfo();
            }
        };
    
    @Override
    public void onDestroy() {
        Log.i(LOG_TAG, "Destroying AvenderService");
        super.onDestroy();
    }
}
