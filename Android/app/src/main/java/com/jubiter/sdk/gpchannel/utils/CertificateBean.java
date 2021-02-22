package com.jubiter.sdk.gpchannel.utils;

/**
 * @Date 2021-02-22  10:39
 * @Author ZJF
 * @Version 1.0
 */
public class CertificateBean {
    private String sn;
    private String subjectID;

    public CertificateBean() {
    }

    public CertificateBean(String sn, String subjectID) {
        this.sn = sn;
        this.subjectID = subjectID;
    }

    public String getSn() {
        return sn;
    }

    public void setSn(String sn) {
        this.sn = sn;
    }

    public String getSubjectID() {
        return subjectID;
    }

    public void setSubjectID(String subjectID) {
        this.subjectID = subjectID;
    }
}
