package com.jubiter.sdk.gpchannel.utils;

/**
 * @Date 2021-02-22  10:54
 * @Author ZJF
 * @Version 1.0
 */
public class InitParamsBean {
    private String scpID;
    private String keyUsage;
    private String keyType;
    private int keyLength;
    private String hostID;
    private String crt;
    private String sk;
    private String cardGroupID;

    public InitParamsBean() {
    }

    public InitParamsBean(String scpID, String keyUsage, String keyType, int keyLength, String hostID, String crt, String sk, String cardGroupID) {
        this.scpID = scpID;
        this.keyUsage = keyUsage;
        this.keyType = keyType;
        this.keyLength = keyLength;
        this.hostID = hostID;
        this.crt = crt;
        this.sk = sk;
        this.cardGroupID = cardGroupID;
    }

    public String getScpID() {
        return scpID;
    }

    public void setScpID(String scpID) {
        this.scpID = scpID;
    }

    public String getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(String keyUsage) {
        this.keyUsage = keyUsage;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    public String getHostID() {
        return hostID;
    }

    public void setHostID(String hostID) {
        this.hostID = hostID;
    }

    public String getCrt() {
        return crt;
    }

    public void setCrt(String crt) {
        this.crt = crt;
    }

    public String getSk() {
        return sk;
    }

    public void setSk(String sk) {
        this.sk = sk;
    }

    public String getCardGroupID() {
        return cardGroupID;
    }

    public void setCardGroupID(String cardGroupID) {
        this.cardGroupID = cardGroupID;
    }
}
