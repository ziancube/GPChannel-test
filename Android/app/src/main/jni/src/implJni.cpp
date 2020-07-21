//
// Created by FT on 2018/4/16.
//

#include <jni.h>
#include <logUtils.h>
#include <GPChannelSDK.h>
#include <jsoncpp/include/json/json.h>
#include <jsoncpp/include/json/value.h>
#include <mSIGNA/stdutils/uchar_vector.h>

// 保存 JavaVM
JavaVM *g_vm = NULL;
int errorCode = 0;

JNIEXPORT jint JNICALL native_getErrorCode(JNIEnv *env, jclass obj) {
    return errorCode;
}

JNIEXPORT jint  JNICALL native_GPC_Initialize(JNIEnv *env, jclass obj,
                                              jstring jJSON) {
    if (NULL == jJSON) {
        return JUBR_ARGUMENTS_BAD;
    }
    int length = env->GetStringLength(jJSON);
    if (0 == length) {
        return JUBR_ARGUMENTS_BAD;
    }

    JUB_CHAR_PTR pJSON = const_cast<JUB_CHAR_PTR>(env->GetStringUTFChars(jJSON, NULL));

    Json::Reader reader;
    Json::Value root;
    reader.parse(pJSON, root);

    GPC_SCP11_SHAREDINFO sharedInfo;
    sharedInfo.scpID = (JUB_CHAR_PTR) root["scpID"].asCString();
    sharedInfo.keyUsage = (JUB_CHAR_PTR) root["keyUsage"].asCString();
    sharedInfo.keyType = (JUB_CHAR_PTR) root["keyType"].asCString();
    JUB_UINT16 keyLength = (JUB_UINT16) root["keyLength"].asUInt();
    uchar_vector vKeyLength;
    vKeyLength.push_back(keyLength);
    sharedInfo.keyLength = (JUB_CHAR_PTR) vKeyLength.getHex().c_str();

    sharedInfo.hostID = (JUB_CHAR_PTR) root["hostID"].asCString();

    char *p = (char *) root["crt"].asCString();
    uchar_vector vOCECert(p);
    p = (char *) root["sk"].asCString();
    uchar_vector vOCERk(p);
    JUB_RV ret = JUB_GPC_Initialize(sharedInfo,
                                    (JUB_CHAR_PTR) vOCECert.getHex().c_str(),
                                    (JUB_CHAR_PTR) vOCERk.getHex().c_str());
    if (ret != JUBR_OK) {
        LOG_ERR("JUB_GPC_Initialize: %08x", ret);
    }
    env->ReleaseStringUTFChars(jJSON, (const char *) pJSON);
    return static_cast<jint>(ret);
}

JNIEXPORT jint JNICALL native_GPC_Finalize(JNIEnv *env, jclass obj) {
    JUB_RV ret = JUB_GPC_Finalize();
    if (ret != JUBR_OK) {
        LOG_ERR("JUB_GPC_Finalize: %08x", ret);
    }
    return static_cast<jint>(ret);
}

JNIEXPORT jstring JNICALL native_GPC_BuildMutualAuthData(JNIEnv *env, jclass obj) {
    JUB_CHAR_PTR mutualAuthData;
    JUB_RV ret = JUB_GPC_BuildMutualAuthData(&mutualAuthData);
    if (ret != JUBR_OK) {
        LOG_ERR("JUB_GPC_BuildMutualAuthData: %08x", ret);
        errorCode = static_cast<int>(ret);
        return NULL;
    } else {
        jstring result = env->NewStringUTF(mutualAuthData);
        JUB_FreeMemory(mutualAuthData);
        return result;
    }
}

JNIEXPORT jint JNICALL native_GPC_OpenSecureChannel(JNIEnv *env, jclass obj, jstring jResponse) {
    JUB_CHAR_PTR pResponse = const_cast<JUB_CHAR_PTR>(env->GetStringUTFChars(jResponse, NULL));
    JUB_RV ret = JUB_GPC_OpenSecureChannel(pResponse);
    if (ret != JUBR_OK) {
        LOG_ERR("JUB_GPC_OpenSecureChannel: %08x", ret);
    }
    return static_cast<jint>(ret);
}

JNIEXPORT jstring JNICALL
native_GPC_BuildAPDU(JNIEnv *env, jclass obj, jlong jCla, jlong jIns, jlong jP1, jlong jP2,
                     jstring jData) {

    JUB_CHAR_PTR pData = const_cast<JUB_CHAR_PTR>(env->GetStringUTFChars(jData, NULL));

    JUB_CHAR_PTR apdu;
    JUB_RV ret = JUB_GPC_BuildAPDU(jCla, jIns, jP1, jP2, pData, &apdu);
    env->ReleaseStringUTFChars(jData, (const char *) pData);
    if (ret != JUBR_OK) {
        LOG_ERR("JUB_GPC_BuildAPDU: %08x", ret);
        errorCode = static_cast<int>(ret);
        return NULL;
    } else {
        jstring result = env->NewStringUTF(apdu);
        JUB_FreeMemory(apdu);
        return result;
    }
}

JNIEXPORT jstring JNICALL
native_GPC_BuildSafeAPDU(JNIEnv *env, jclass obj, jlong jCla, jlong jIns, jlong jP1, jlong jP2,
                         jstring jData) {
    JUB_CHAR_PTR pData = const_cast<JUB_CHAR_PTR>(env->GetStringUTFChars(jData, NULL));

    JUB_CHAR_PTR apdu;
    JUB_RV ret = JUB_GPC_BuildSafeAPDU(jCla, jIns, jP1, jP2, pData, &apdu);
    env->ReleaseStringUTFChars(jData, (const char *) pData);
    if (ret != JUBR_OK) {
        LOG_ERR("JUB_GPC_BuildSafeAPDU: %08x", ret);
        errorCode = static_cast<int>(ret);
        return NULL;
    } else {
        jstring result = env->NewStringUTF(apdu);
        JUB_FreeMemory(apdu);
        return result;
    }
}

JNIEXPORT jstring JNICALL
native_GPC_ParseSafeAPDUResponse(JNIEnv *env, jclass obj, jstring jResponse) {

    JUB_CHAR_PTR pResponse = const_cast<JUB_CHAR_PTR>(env->GetStringUTFChars(jResponse, NULL));
    JUB_UINT16 wRet = 0;
    JUB_CHAR_PTR response;
    JUB_RV ret = JUB_GPC_ParseSafeAPDUResponse(pResponse, &wRet, &response);
    env->ReleaseStringUTFChars(jResponse, (const char *) pResponse);
    if (ret != JUBR_OK) {
        LOG_ERR("JUB_GPC_ParseSafeAPDUResponse: %08x", ret);
        errorCode = static_cast<int>(ret);
        return NULL;
    } else {
        Json::FastWriter writer;
        Json::Value root;
        root["wRet"] = wRet;
        root["response"] = response;
        jstring result = env->NewStringUTF(writer.write(root).c_str());
        JUB_FreeMemory(response);
        return result;
    }
}

JNIEXPORT jstring JNICALL
native_GPC_ParseAPDUResponse(JNIEnv *env, jclass obj, jstring jResponse) {

    JUB_CHAR_PTR pResponse = const_cast<JUB_CHAR_PTR>(env->GetStringUTFChars(jResponse, NULL));
    JUB_UINT16 wRet = 0;
    JUB_CHAR_PTR resp;
    JUB_RV ret = JUB_GPC_ParseAPDUResponse(pResponse, &wRet, &resp);
    env->ReleaseStringUTFChars(jResponse, (const char *) pResponse);
    if (ret != JUBR_OK) {
        LOG_ERR("JUB_GPC_ParseAPDUResponse: %08x", ret);
        errorCode = static_cast<int>(ret);
        return NULL;
    } else {
        Json::FastWriter writer;
        Json::Value root;
        root["wRet"] = wRet;
        root["response"] = resp;
        jstring result = env->NewStringUTF(writer.write(root).c_str());
        JUB_FreeMemory(resp);
        return result;
    }
}

JNIEXPORT jstring JNICALL
native_GPC_TLVDecode(JNIEnv *env, jclass obj, jstring jApdu) {
    JUB_CHAR_PTR pApdu = const_cast<JUB_CHAR_PTR>(env->GetStringUTFChars(jApdu, NULL));
    JUB_ULONG tag = 0;
    JUB_CHAR_PTR value;
    JUB_RV ret = JUB_GPC_TLVDecode(pApdu, &tag, &value);
    env->ReleaseStringUTFChars(jApdu, (const char *) pApdu);
    if (ret != JUBR_OK) {
        LOG_ERR("JUB_GPC_TLVDecode: %08x", ret);
        errorCode = static_cast<int>(ret);
        return NULL;
    } else {
        Json::FastWriter writer;
        Json::Value root;
        root["tag"] = tag;
        root["value"] = value;
        jstring result = env->NewStringUTF(writer.write(root).c_str());
        JUB_FreeMemory(value);
        return result;
    }
}

/**
 * JNINativeMethod由三部分组成:
 * (1)Java中的函数名;
 * (2)函数签名,格式为(输入参数类型)返回值类型;
 * (3)native函数名
 */
static JNINativeMethod gMethods[] = {
        {
                "nativeGetErrorCode",
                "()I",
                (void *) native_getErrorCode
        },
        {
                "nativeGPCInitialize",
                "(Ljava/lang/String;)I",
                (void *) native_GPC_Initialize
        },
        {
                "nativeGPCFinalize",
                "()I",
                (void *) native_GPC_Finalize
        },
        {
                "nativeGPCBuildMutualAuthData",
                "()Ljava/lang/String;",
                (void *) native_GPC_BuildMutualAuthData
        },
        {
                "nativeGPCOpenSecureChannel",
                "(Ljava/lang/String;)I",
                (void *) native_GPC_OpenSecureChannel
        },
        {
                "nativeGPCBuildAPDU",
                "(JJJJLjava/lang/String;)Ljava/lang/String;",
                (void *) native_GPC_BuildAPDU
        },
        {
                "nativeGPCBuildSafeAPDU",
                "(JJJJLjava/lang/String;)Ljava/lang/String;",
                (void *) native_GPC_BuildSafeAPDU
        },
        {
                "nativeGPCParseSafeAPDUResponse",
                "(Ljava/lang/String;)Ljava/lang/String;",
                (void *) native_GPC_ParseSafeAPDUResponse
        },
        {
                "nativeGPCParseAPDUResponse",
                "(Ljava/lang/String;)Ljava/lang/String;",
                (void *) native_GPC_ParseAPDUResponse
        },
        {
                "nativeGPCTLVDecode",
                "(Ljava/lang/String;)Ljava/lang/String;",
                (void *) native_GPC_TLVDecode
        }
};


#define NATIVE_API_CLASS "com/jubiter/sdk/gpchannel/GPChannelNatives"

/**
 * JNI_OnLoad 默认会在 System.loadLibrary 过程中自动调用到，因而可利用此函数，进行动态注册
 * JNI 版本的返回视对应 JDK 版本而定
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint ret = JNI_FALSE;

    // 获取 env 指针
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return ret;
    }

    // 保存全局 JVM 以便在动态注册的皆空中使用 env 环境
    env->GetJavaVM(&g_vm);

    // 获取类引用
    jclass clazz = env->FindClass(NATIVE_API_CLASS);
    if (clazz == NULL) {
        return ret;
    }

    // 注册 JNI 方法
    if (env->RegisterNatives(clazz, gMethods, sizeof(gMethods) / sizeof(gMethods[0])) < JNI_OK) {
        return ret;
    }
    // 成功
    return JNI_VERSION_1_6;
}