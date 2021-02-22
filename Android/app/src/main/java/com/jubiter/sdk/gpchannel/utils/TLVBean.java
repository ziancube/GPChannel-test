package com.jubiter.sdk.gpchannel.utils;

/**
 * @Date 2021-02-22  10:38
 * @Author ZJF
 * @Version 1.0
 */
public class TLVBean {
    private long tag;
    private String value;

    public TLVBean() {
    }

    public TLVBean(long tag, String value) {
        this.tag = tag;
        this.value = value;
    }

    public long getTag() {
        return tag;
    }

    public void setTag(long tag) {
        this.tag = tag;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
