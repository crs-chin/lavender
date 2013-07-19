/*
 * VerdictInfo.java
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

import android.os.Parcel;
import android.os.Parcelable;

import com.javender.VerdictReq;

public class VerdictInfo implements Parcelable{
    public byte[] rid;
    public int[] pid;
    public int[] uid;
    public String[] exe;
    public long time;

    public VerdictInfo(VerdictReq req)  {
        rid = req.rid;
        pid = req.pid;
        uid = req.uid;
        exe = req.exe;
        time = req.time;
    }

    public VerdictInfo(Parcel in)  {
        rid = in.createByteArray();
        pid = in.createIntArray();
        uid = in.createIntArray();
        exe = in.createStringArray();
        time = in.readLong();
    }

    @Override
    public int describeContents()  {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel out, int flags)  {
        out.writeByteArray(rid);
        out.writeIntArray(pid);
        out.writeIntArray(pid);
        out.writeStringArray(exe);
        out.writeLong(time);
    }

    public static final Parcelable.Creator<VerdictInfo> CREATOR =
        new Parcelable.Creator<VerdictInfo>()  {
            public VerdictInfo createFromParcel(Parcel in) {
                return new VerdictInfo(in);
            }

            public VerdictInfo[] newArray(int size) {
                return new VerdictInfo[size];
            }
    };
}

