/*
 * IAvenderService.java
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

import com.android.avender.VerdictInfo;
 
interface IAvenderService {
	/**
     * connect to Lavender service if not yet
     */
    boolean connect();
 
 	/**
     * connect to Lavender service if not yet
     */
    boolean getConnectState();

 	/**
     * get next verdict if available
     */
    VerdictInfo getVerdict();

    boolean setVerdict(in byte[] rid, int verd);

 	/**
     * enable/disable specific log type
     */
    boolean setLogTypeEnable(int type, boolean stat);
    boolean getLogTypeEnable(int type);

 	/**
     * enable/disable specific log level
     */
    boolean setLogLevelEnable(int level, boolean stat);
    boolean getLogLevelEnable(int level);

    /**
     * connect to Lavender service if not yet
     */
    boolean getCactusState();

    /**
     * connect to Lavender service if not yet
     */
    boolean setCactusState(boolean st);    

    /**
     * start lavender service if not started yet
     */
    void startLavender();
    
    /**
     * stop lavender service if not stopped yet
     */
    void stopLavender();
 
    /**
     * get lavender version info
     */
    String versionInfo();
    
    /**
     * TODO: more interface to be defined
     */
}
