/*
 * MainActivity.java
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

import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.BroadcastReceiver;
import android.content.IntentFilter;
import android.view.View;
import android.view.Menu;
import android.widget.Button;
import android.widget.TextView;
import android.util.Log;

import com.android.avender.VerdictRequest;
import com.javender.Javender;

public class MainActivity extends Activity {

    private final String LOG_TAG = "AVENDER";

    private IAvenderService avenderService = null;
    private BroadcastReceiver mReceiver = null;

    private class ConnectStateReceiver extends BroadcastReceiver{
        @Override
        public void onReceive(Context ctx, Intent intent)  {
            if(intent.getAction().equals("android.intent.action.LavenderStateChange"))  {
                Log.i(LOG_TAG, "Lavender state changed, update");
                updateView();
            }
        }
    }

    private void updateView()  {
    	TextView v;
    	Button b;

        if(avenderService == null)  {
        	v = (TextView)findViewById(R.id.cactus_status_switch);
        	v.setText(R.string.enable_cactus);
        	v = (TextView)findViewById(R.id.lavender_service_switch);
        	v.setText(R.string.start_lavender);
			v = (TextView)findViewById(R.id.version_info);
			v.setText(R.string.service_unavailable);

        	b = (Button)findViewById(R.id.cactus_status_switch);
        	b.setEnabled(false);
        	b = (Button)findViewById(R.id.lavender_service_switch);
        	b.setEnabled(false);
        	b = (Button)findViewById(R.id.main_log);
        	b.setEnabled(false);
        	b = (Button)findViewById(R.id.rtnl_log);
        	b.setEnabled(false);
        	b = (Button)findViewById(R.id.uevent_log);
        	b.setEnabled(false);
        	b = (Button)findViewById(R.id.conntrack_log);
        	b.setEnabled(false);
        }else  {
	        try {
				if(avenderService.getConnectState())  {
					v = (TextView)findViewById(R.id.cactus_status_switch);
					v.setText(avenderService.getCactusState() ? R.string.disable_cactus : R.string.enable_cactus);
					v = (TextView)findViewById(R.id.lavender_service_switch);
					v.setText(R.string.stop_lavender);

					v = (TextView)findViewById(R.id.main_log);
					v.setText(avenderService.getLogTypeEnable(Javender.LOG_MAIN) ? R.string.disable_main_log : R.string.enable_main_log);
					v = (TextView)findViewById(R.id.rtnl_log);
					v.setText(avenderService.getLogTypeEnable(Javender.LOG_RTNL) ? R.string.disable_rtnl_log : R.string.enable_rtnl_log);
					v = (TextView)findViewById(R.id.uevent_log);
					v.setText(avenderService.getLogTypeEnable(Javender.LOG_UEVENT) ? R.string.disable_uevent_log : R.string.enable_uevent_log);
					v = (TextView)findViewById(R.id.conntrack_log);
					v.setText(avenderService.getLogTypeEnable(Javender.LOG_CONNTRACK) ? R.string.disable_conntrack_log : R.string.enable_conntrack_log);

					v = (TextView)findViewById(R.id.version_info);
					v.setText(avenderService.versionInfo());

		        	b = (Button)findViewById(R.id.cactus_status_switch);
		        	b.setEnabled(true);
		        	b = (Button)findViewById(R.id.lavender_service_switch);
		        	b.setEnabled(true);
                    b = (Button)findViewById(R.id.main_log);
                    b.setEnabled(true);
                    b = (Button)findViewById(R.id.rtnl_log);
                    b.setEnabled(true);
                    b = (Button)findViewById(R.id.uevent_log);
                    b.setEnabled(true);
                    b = (Button)findViewById(R.id.conntrack_log);
                    b.setEnabled(true);
				}else  {
					v = (TextView)findViewById(R.id.cactus_status_switch);
					v.setText(R.string.enable_cactus);
					v = (TextView)findViewById(R.id.lavender_service_switch);
					v.setText(R.string.start_lavender);
					v = (TextView)findViewById(R.id.version_info);
					v.setText(R.string.service_disconnected);
					
					b = (Button)findViewById(R.id.cactus_status_switch);
		        	b.setEnabled(false);
		        	b = (Button)findViewById(R.id.lavender_service_switch);
		        	b.setEnabled(true);
                    b = (Button)findViewById(R.id.main_log);
                    b.setEnabled(false);
                    b = (Button)findViewById(R.id.rtnl_log);
                    b.setEnabled(false);
                    b = (Button)findViewById(R.id.uevent_log);
                    b.setEnabled(false);
                    b = (Button)findViewById(R.id.conntrack_log);
                    b.setEnabled(false);
				}
			} catch (RemoteException e) {
				e.printStackTrace();
	        	b = (Button)findViewById(R.id.cactus_status_switch);
	        	b.setEnabled(false);
	        	b = (Button)findViewById(R.id.lavender_service_switch);
	        	b.setEnabled(false);
                b = (Button)findViewById(R.id.main_log);
                b.setEnabled(false);
                b = (Button)findViewById(R.id.rtnl_log);
                b.setEnabled(false);
                b = (Button)findViewById(R.id.uevent_log);
                b.setEnabled(false);
                b = (Button)findViewById(R.id.conntrack_log);
                b.setEnabled(false);
				v = (TextView)findViewById(R.id.version_info);
				v.setText(R.string.service_unavailable);
			}
        }
    }
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        startService(new Intent(this, AvenderService.class));
    	bindService(new Intent(this, AvenderService.class), sc, Context.BIND_AUTO_CREATE);
        mReceiver = new ConnectStateReceiver();
        registerReceiver(mReceiver, new IntentFilter("android.intent.action.LavenderStateChange"));
        updateView();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        //getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    public void onCactusStatusSwitchClick(View view) {
        if(avenderService != null)  {
            try {
                if(avenderService.getConnectState())  {
                    if(avenderService.getCactusState())  {
                        Log.i(LOG_TAG, "toggle inactive Cactus service state");
                        avenderService.setCactusState(false);
                    }else  {
                        Log.i(LOG_TAG, "toggle active Cactus service state");
                        avenderService.setCactusState(true);
                    }
                }
            } catch (RemoteException e) {
				e.printStackTrace();
            }
        }
        updateView();
    }
    
    public void onLavenderServiceSwitchClick(View view) {
    	if(avenderService != null)  {
            try{
                if(avenderService.getConnectState())  {
                    Log.i(LOG_TAG, "toggle stop Lavender service state");
                    avenderService.stopLavender();
                }else  {
                    Log.i(LOG_TAG, "toggle start Lavender service state");
                    avenderService.startLavender();
                }
            }catch (RemoteException e)  {
                e.printStackTrace();
            }
        }
        updateView();
    }

    public void onMainLogSwitchClick(View view) {
    	if(avenderService != null)  {
            try{
                if(avenderService.getLogTypeEnable(Javender.LOG_MAIN))  {
                    Log.i(LOG_TAG, "toggle disable MAIN log");
                    avenderService.setLogTypeEnable(Javender.LOG_MAIN, false);
                }else  {
                    Log.i(LOG_TAG, "toggle enable MAIN log");
                    avenderService.setLogTypeEnable(Javender.LOG_MAIN, true);
                }
            }catch (RemoteException e)  {
                e.printStackTrace();
            }
        }
        updateView();
    }

    public void onRTNLLogSwitchClick(View view) {
    	if(avenderService != null)  {
            try{
                if(avenderService.getLogTypeEnable(Javender.LOG_RTNL))  {
                    Log.i(LOG_TAG, "toggle disable RTNL log");
                    avenderService.setLogTypeEnable(Javender.LOG_RTNL, false);
                }else  {
                    Log.i(LOG_TAG, "toggle enable RTNL log");
                    avenderService.setLogTypeEnable(Javender.LOG_RTNL, true);
                }
            }catch (RemoteException e)  {
                e.printStackTrace();
            }
        }
        updateView();
    }

    public void onUEventLogSwitchClick(View view) {
    	if(avenderService != null)  {
            try{
                if(avenderService.getLogTypeEnable(Javender.LOG_UEVENT))  {
                    Log.i(LOG_TAG, "toggle disable UEvent log");
                    avenderService.setLogTypeEnable(Javender.LOG_UEVENT, false);
                }else  {
                    Log.i(LOG_TAG, "toggle enable UEvent log");
                    avenderService.setLogTypeEnable(Javender.LOG_UEVENT, true);
                }
            }catch (RemoteException e)  {
                e.printStackTrace();
            }
        }
        updateView();
    }

    public void onCONNTRACKLogSwitchClick(View view) {
    	if(avenderService != null)  {
            try{
                if(avenderService.getLogTypeEnable(Javender.LOG_CONNTRACK))  {
                    Log.i(LOG_TAG, "toggle disable CONNTRACK log");
                    avenderService.setLogTypeEnable(Javender.LOG_CONNTRACK, false);
                }else  {
                    Log.i(LOG_TAG, "toggle enable CONNTRACK log");
                    avenderService.setLogTypeEnable(Javender.LOG_CONNTRACK, true);
                }
            }catch (RemoteException e)  {
                e.printStackTrace();
            }
        }
        updateView();
    }
    
    private ServiceConnection sc = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                Log.i(LOG_TAG, "AvenderService connected up");
                avenderService = IAvenderService.Stub.asInterface(service);
                updateView();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                Log.i(LOG_TAG, "AvenderService disconnected");
                avenderService = null;
                updateView();
            }
        };
}
