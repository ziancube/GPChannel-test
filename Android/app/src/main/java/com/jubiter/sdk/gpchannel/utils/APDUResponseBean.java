package com.jubiter.sdk.gpchannel.utils;

/**
 * @Date 2021-02-22  10:36
 * @Author ZJF
 * @Version 1.0
 */
public class APDUResponseBean {
    private int wRet;
    private String response;

    public APDUResponseBean() {
    }

    public APDUResponseBean(int wRet, String response) {
        this.wRet = wRet;
        this.response = response;
    }

    public int getwRet() {
        return wRet;
    }

    public void setwRet(int wRet) {
        this.wRet = wRet;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }
}
