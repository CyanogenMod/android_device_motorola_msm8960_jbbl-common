/*
 * Copyright (C) 2013 The CyanogenMod Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.telephony;

import static com.android.internal.telephony.RILConstants.*;

import android.content.Context;
import android.os.AsyncResult;
import android.os.Message;
import android.os.Parcel;
import android.text.TextUtils;
import android.telephony.Rlog;
import android.telephony.SignalStrength;

import java.util.ArrayList;

/*
 * Custom Qualcomm RIL for Motorola MSM8960 phones
 *
 * {@hide}
 */
public class MotorolaQualcommRIL extends RIL implements CommandsInterface {

    private boolean setPreferredNetworkTypeSeen = false;

    public MotorolaQualcommRIL(Context context, int preferredNetworkType,
            int cdmaSubscription, Integer instanceId) {
        super(context, preferredNetworkType, cdmaSubscription, instanceId);
    }

    public MotorolaQualcommRIL(Context context, int networkMode, int cdmaSubscription) {
        this(context, networkMode, cdmaSubscription, null);
    }

    @Override
    protected Object
    responseOperatorInfos(Parcel p) {
        String strings[] = (String [])responseStrings(p);
        ArrayList<OperatorInfo> ret;
        ArrayList<String> mccmnc;
        int mQANElements = 5; // fifth element is network generation - 2G/3G/(4G?)

        if (strings.length % mQANElements != 0) {
            throw new RuntimeException(
                "RIL_REQUEST_QUERY_AVAILABLE_NETWORKS: invalid response. Got "
                + strings.length + " strings, expected multiple of " + mQANElements);
        }

        ret = new ArrayList<OperatorInfo>();
        mccmnc = new ArrayList<String>();

        for (int i = 0 ; i < strings.length ; i += mQANElements) {
            /* add each operator only once - the parcel contains separate entries
               for 2G and 3G networks, we need just the list of available operators */
            if (!mccmnc.contains(strings[i+2])) {
                ret.add (
                    new OperatorInfo(
                        strings[i+0],
                        strings[i+1],
                        strings[i+2],
                        strings[i+3]));
                mccmnc.add(strings[i+2]);
            }
        }

        return ret;
    }

    @Override
    protected Object
    responseSignalStrength(Parcel p) {

        int parcelSize = p.dataSize();
        int gsmSignalStrength = p.readInt();
        int gsmBitErrorRate = p.readInt();
        int cdmaDbm = p.readInt();
        int cdmaEcio = p.readInt();
        int evdoDbm = p.readInt();
        int evdoEcio = p.readInt();
        int evdoSnr = p.readInt();
        int lteSignalStrength = p.readInt();
        int lteRsrp = p.readInt();
        int lteRsrq = p.readInt();
        int lteRssnr = p.readInt();
        int lteCqi = p.readInt();
        boolean isGsm = (mPhoneType == RILConstants.GSM_PHONE);

        SignalStrength signalStrength = new SignalStrength(gsmSignalStrength,
                gsmBitErrorRate, cdmaDbm, cdmaEcio, evdoDbm, evdoEcio, evdoSnr,
                lteSignalStrength, lteRsrp, lteRsrq, lteRssnr, lteCqi, isGsm);

        return signalStrength;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void getCellInfoList(Message result) {
        riljLog("MotoQcRIL: getCellInfoList: not supported");
        if (result != null) {
            CommandException ex = new CommandException(
                CommandException.Error.REQUEST_NOT_SUPPORTED);
            AsyncResult.forMessage(result, null, ex);
            result.sendToTarget();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setCellInfoListRate(int rateInMillis, Message response) {
        riljLog("MotoQcRIL: setCellInfoListRate: not supported");
        if (response != null) {
            CommandException ex = new CommandException(
                CommandException.Error.REQUEST_NOT_SUPPORTED);
            AsyncResult.forMessage(response, null, ex);
            response.sendToTarget();
        }
    }

    @Override
    public void setInitialAttachApn(String apn, String protocol, int authType, String username,
            String password, Message result) {
        riljLog("MotoQcRIL: setInitialAttachApn: not supported");
        if (result != null) {
            CommandException ex = new CommandException(
                CommandException.Error.REQUEST_NOT_SUPPORTED);
            AsyncResult.forMessage(result, null, ex);
            result.sendToTarget();
        }
    }

    @Override
    public void getImsRegistrationState(Message result) {
        riljLog("MotoQcRIL: getImsRegistrationState: not supported");
        if (result != null) {
            CommandException ex = new CommandException(
                CommandException.Error.REQUEST_NOT_SUPPORTED);
            AsyncResult.forMessage(result, null, ex);
            result.sendToTarget();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setDataAllowed(boolean allowed, Message result) {
        riljLog("MotoQcRIL: setDataAllowed: not supported");
        if (result != null) {
            CommandException e = new CommandException(
                CommandException.Error.REQUEST_NOT_SUPPORTED);
            AsyncResult.forMessage(result, null, e);
            result.sendToTarget();
        }
    }

    @Override
    public void getHardwareConfig (Message result) {
        riljLog("MotoQcRIL: getHardwareConfig: not supported");
        if (result != null) {
            CommandException e = new CommandException(
                CommandException.Error.REQUEST_NOT_SUPPORTED);
            AsyncResult.forMessage(result, null, e);
            result.sendToTarget();
        }
    }

    @Override
    public void setPreferredNetworkType(int networkType, Message response) {
        riljLog("MotoQcRIL: setPreferredNetworkType: " + networkType);
        if (!setPreferredNetworkTypeSeen) {
            setPreferredNetworkTypeSeen = true;
        }
        super.setPreferredNetworkType(networkType, response);
    }

    @Override
    public void getRadioCapability (Message response) {
        riljLog("MotoQcRIL: getRadioCapability");
        if (response != null) {
            Object ret = makeStaticRadioCapability();
            AsyncResult.forMessage(response, ret, null);
            response.sendToTarget();
        }
    }

    @Override
    public void startLceService(int reportIntervalMs, boolean pullMode, Message response) {
        riljLog("MotoQcRIL: startLceService: not supported");
        if (response != null) {
            CommandException e = new CommandException(
                CommandException.Error.REQUEST_NOT_SUPPORTED);
            AsyncResult.forMessage(response, null, e);
            response.sendToTarget();
        }
    }

    @Override
    public void iccOpenLogicalChannel(String AID, Message response) {
        riljLog("MotoQcRIL: iccOpenLogicalChannel: not supported");
        if (response != null) {
            CommandException e = new CommandException(
                CommandException.Error.REQUEST_NOT_SUPPORTED);
            AsyncResult.forMessage(response, null, e);
            response.sendToTarget();
        }
    }

    @Override
    protected void
    processUnsolicited (Parcel p) {
        int dataPosition = p.dataPosition(); // save off position within the Parcel
        int response;

        response = p.readInt();

        switch(response) {
            case RIL_UNSOL_RIL_CONNECTED:
                if (!setPreferredNetworkTypeSeen) {
                    Rlog.v(RILJ_LOG_TAG, "MotoQcRIL: connected, setting network type to " + mPreferredNetworkType);
                    setPreferredNetworkType(mPreferredNetworkType, null);
                }
                break;
        }

        p.setDataPosition(dataPosition);
        super.processUnsolicited(p);
    }
}
