// GPChannelSDK_test_scp11.cpp : Defines the entry point for the console application.
//

#ifdef _WIN32
#include "stdafx.h"
#endif


#include "GPChannelSDK_main.h"

#include "scp11/scp11c.hpp"

#include "mSIGNA/stdutils/uchar_vector.h"


using std::getline;
using std::istringstream;


void scp11_tlv_test() {

    JUB_RV rv = JUBR_ERROR;

    // GET DEVICE CERTIFICATE : 80 CA BF 21 //////////////////////////////////////////////
    JUB_CHAR_PTR tlv = (JUB_CHAR_PTR)"bf2181dc7f2181d8931042584e46433230303532353030303031420d6a75626974657277616c6c65745f200d6a75626974657277616c6c65749501825f2504202005255f24042025052453007f4946b0410479704bdb2d3da2e547eb6de66e0073f6e61ae32076af007973b5fa1dbe07e0ef38bd84d85f1fe1e1410ff743e659691b36361c76bee2fac44fd88825759268cef001005f37483046022100b076674c9f0ea1ddee84517e2a53cb392ac2c8b25ca3a7d56558570a051737020221008a982e267ffcef5309a272ea492be489a233381c477e8803034a8f6789f2bbd9";
    JUB_ULONG tag = 0;
    JUB_CHAR_PTR value;
    rv = JUB_GPC_TLVDecode(tlv, &tag, &value);
    std::cout << "JUB_GPC_TLVDecode return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }
    uchar_vector vDeviceCert = uchar_vector(value);
    std::cout << "[" << tag << "]" << "[" << vDeviceCert.size() << "]: " << vDeviceCert.getHex() << std::endl;
    JUB_FreeMemory(value);
}


void scp11_process_sample(const char* json_file) {

    JUB_RV rv = JUBR_ERROR;

    Json::Value root = readJSON(json_file);

    // 1. Initialize /////////////////////////////////////////////////////////////////////
    // JUB_GPC_Initialize() is called when it is ready to start the secure channel.
    GPC_SCP11_SHAREDINFO sharedInfo;
    sharedInfo.scpID = (JUB_CHAR_PTR)"1107";
    sharedInfo.keyUsage = (JUB_CHAR_PTR)"3C";
    sharedInfo.keyType = (JUB_CHAR_PTR)"88";
    JUB_UINT16 keyLength = root["SCP11c"]["KeyLength"].asUInt();
    uchar_vector vKeyLength;
    vKeyLength.push_back(keyLength);
    sharedInfo.keyLength = (JUB_CHAR_PTR)vKeyLength.getHex().c_str();
    sharedInfo.hostID = (char*)root["SCP11c"]["HostID"].asCString();

    char* p = (char*)root["SCP11c"]["OCE"][1][0].asCString();
    uchar_vector vOCECert(p);
    p = (char*)root["SCP11c"]["OCE"][1][2].asCString();
    uchar_vector vOCERk(p);
    rv = JUB_GPC_Initialize(sharedInfo,
                            (JUB_CHAR_PTR)vOCECert.getHex().c_str(),
                            (JUB_CHAR_PTR)vOCERk.getHex().c_str());
    std::cout << "JUB_GPC_Initialize return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }

    // 2. PerformSecurityOperation: 80 2A 18 10 //////////////////////////////////////////
    //    ------------------------------------------------
    //    80 2A 18 10 EC
    //    7F 21 81 E8 93 10 43 45  52 54 5F 41 50 50 5F 45
    //    43 4B 41 30 30 31 42 0D  6A 75 62 69 74 65 72 77
    //    61 6C 6C 65 74 5F 20 0D  6A 75 62 69 74 65 72 77
    //    61 6C 6C 65 74 95 02 00  80 5F 25 04 20 20 05 25
    //    5F 24 04 20 25 05 24 53  00 BF 20 0E EF 0C 8D 0A
    //    82 01 82 02 82 03 82 04  82 05 7F 49 46 B0 41 04
    //    8F D3 FA B3 90 7C 5C C8  CD 19 3E B2 B6 53 EA 17
    //    91 15 B7 F3 05 C9 E2 1D  E6 D2 9C 07 36 A3 B8 20
    //    25 B2 19 F2 4B DA 86 D8  0F 5A E2 62 52 1E 12 4F
    //    4C 66 91 A0 C4 7B 1F B7  2D 95 89 5E 93 12 CB 0D
    //    F0 01 00 5F 37 46 30 44  02 20 4D 75 EA A2 F0 96
    //    04 A9 59 7D A9 05 D6 80  EB 61 9B 8A DC F0 80 E5
    //    AD 69 50 E1 DB F2 61 95  C9 E2 02 20 67 64 9A FB
    //    4A 8B C3 80 B3 82 52 04  99 C6 F2 BB 35 0A 85 19
    //    B0 EC DB E0 B7 37 4A A8  98 82 6D 0E
    //    ==================== EXPECT ====================
    JUB_CHAR_PTR apduPSO;
    rv = JUB_GPC_BuildAPDU(0x80, 0x2A, 0x18, 0x10,
                           (JUB_CHAR_PTR)vOCECert.getHex().c_str(),
                           &apduPSO);
    std::cout << "JUB_GPC_BuildAPDU return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }
    std::cout << "Perform Security Operation APDU[" << uchar_vector(apduPSO).size() << "]: " << apduPSO << std::endl;
    JUB_FreeMemory(apduPSO);

    // 3. MutualAuthenticate: 80 82 18 15 ////////////////////////////////////////////////
    JUB_CHAR_PTR mutualAuthData;
    rv = JUB_GPC_BuildMutualAuthData(&mutualAuthData);
    std::cout << "JUB_GPC_BuildMutualAuthData return " << rv << std::endl;
    if (JUBR_OK != rv) {
        JUB_FreeMemory(apduPSO);
        return ;
    }
    std::cout << "MutualAuth Data[" << uchar_vector(mutualAuthData).size() << "]: " << mutualAuthData << std::endl;

    //    ------------------------------------------------
    //    80 82 18 15 5d
    //    a6 17 90 02 11 07 95 01  3c 80 01 88 81 01 10 84
    //    08 80 80 80 80 80 80 80  80 5f 49 41 04 57 6f 1a
    //    98 8d c0 0a d9 b5 53 3b  16 59 c7 94 35 61 02 19
    //    da 2a b3 7b 43 d6 92 dc  13 39 cd c1 31 f1 20 50
    //    83 53 f6 0b 9a d7 dc 5e  00 12 15 f5 8c 00 57 cd
    //    23 37 5e fe 96 1d 77 72  fe 58 16 23 20
    //    ==================== EXPECT ====================
    JUB_CHAR_PTR apduMA;
    rv = JUB_GPC_BuildAPDU(0x80, 0x82, 0x18, 0x15,
                           mutualAuthData,
                           &apduMA);
    std::cout << "JUB_GPC_BuildAPDU return " << rv << std::endl;
    if (JUBR_OK != rv) {
        JUB_FreeMemory(mutualAuthData);
        return ;
    }
    std::cout << "MutualAuthenticate APDU[" << uchar_vector(apduMA).size() << "]: " << apduMA << std::endl;
    JUB_FreeMemory(mutualAuthData);
    JUB_FreeMemory(apduMA);

    //    [COMM] RECV 7
    //    ------------------------------------------------
    //    5F 49 41 04 79 70 4B DB  2D 3D A2 E5 47 EB 6D E6
    //    6E 00 73 F6 E6 1A E3 20  76 AF 00 79 73 B5 FA 1D
    //    BE 07 E0 EF 38 BD 84 D8  5F 1F E1 E1 41 0F F7 43
    //    E6 59 69 1B 36 36 1C 76  BE E2 FA C4 4F D8 88 25
    //    75 92 68 CE 86 10 64 5B  F0 A0 FF E7 1D 30 0B CD
    //    07 D8 9C 5B 20 A9 90 00
    //    No error
    //    response matches with expectation
    //    elapsed 656.000 ms
    //    ++++++++++++++++++++++++++++++++++++++++++++++++
    JUB_CHAR_CPTR maResponseData = "5F49410479704BDB2D3DA2E547EB6DE66E0073F6E61AE32076AF007973B5FA1DBE07E0EF38BD84D85F1FE1E1410FF743E659691B36361C76BEE2FAC44FD88825759268CE8610645BF0A0FFE71D300BCD07D89C5B20A99000";
    JUB_UINT16 wRet = 0;
    JUB_CHAR_PTR maResponse;
    rv = JUB_GPC_ParseAPDUResponse(maResponseData, &wRet, &maResponse);
    std::cout << "JUB_GPC_ParseAPDUResponse return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }
    uchar_vector vResp(maResponse);
    std::cout << "MutualAuthenticate APDU Resp[" << wRet << "]" << std::endl;
    std::cout << "MutualAuthenticate APDU Resp[" << vResp.size() << "]: " << maResponse << std::endl;

    // 4. OpenSecureChannel //////////////////////////////////////////////////////////////
    rv = JUB_GPC_OpenSecureChannel(maResponse);
    std::cout << "JUB_GPC_OpenSecureChannel return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }
    JUB_FreeMemory(maResponse);

    // 5. Secure channel APDU /////////////////////////////////////////////////////////
    // JUB_GPC_BuildSafeAPDU() and JUB_GPC_ParseSafeAPDUResponse() MUST be called in pairs.
    // Non-ciphertext APDU can be interspersed between ciphertext APDUs in the channel.
    // Verify PIN: 80 20 00 00 ////////////////////////////////////////////////////////
    //    ------------------------------------------------
    //    84 20 00 00 18
    //    4b 25 1c 59 21 0b 67 4d  ee 52 c5 80 d8 ef 01 77
    //    cd b6 7e f6 05 bf 67 ff
    //    ==================== EXPECT ====================
    JUB_CHAR_PTR apduSafeVerifyPIN;
    rv = JUB_GPC_BuildSafeAPDU(0x80, 0x20, 0x00, 0x00,
                               "0435353535",
                               &apduSafeVerifyPIN);
    std::cout << "JUB_GPC_BuildSafeAPDU return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }
    uchar_vector vApduSafeVerifyPIN(apduSafeVerifyPIN);
    std::cout << "SafeVerifyPIN APDU[" << vApduSafeVerifyPIN.size() << "]: " << apduSafeVerifyPIN << std::endl;
    JUB_FreeMemory(apduSafeVerifyPIN);

    // Verify PIN Reponse /////////////////////////////////////////////////////////////
    //    [COMM] RECV 8
    //    ------------------------------------------------
    //    4C E5 5D EE 47 18 BC D0  01 0E AC 79 42 32 47 5C
    //    5B F4 6D 9E 0B BA 68 34  90 00
    //    No error
    //    response matches with expectation
    //    elapsed 24.000 ms
    //    ++++++++++++++++++++++++++++++++++++++++++++++++
    JUB_CHAR_PTR apduResponse = (JUB_CHAR_PTR)"4CE55DEE4718BCD0010EAC794232475C5BF46D9E0BBA68349000";
    wRet = 0;
    JUB_CHAR_PTR response;
    rv = JUB_GPC_ParseSafeAPDUResponse(apduResponse, &wRet, &response);
    std::cout << "JUB_GPC_ParseSafeAPDUResponse return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }
    vResp.clear();
    vResp = uchar_vector(response);
    std::cout << "SafeVerifyPIN APDU Resp[" << wRet << "]" << std::endl;
    std::cout << "SafeVerifyPIN APDU Resp[" << vResp.size() << "]: " << response << std::endl;
    JUB_FreeMemory(apduResponse);
    JUB_FreeMemory(response);

    // Verify PIN: 80 20 00 00 ////////////////////////////////////////////////////////
    //    ------------------------------------------------
    //    84 20 00 00 18
    //    ee 5d 8b 0b 57 ed 45 5f  03 62 b5 1b e6 f7 96 e3
    //    09 5b 9f f3 16 82 8e 34
    //    ==================== EXPECT ====================
    rv = JUB_GPC_BuildSafeAPDU(0x80, 0x20, 0x00, 0x00,
                               "0435353535",
                               &apduSafeVerifyPIN);
    std::cout << "JUB_GPC_BuildSafeAPDU return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }
    vApduSafeVerifyPIN.clear();
    vApduSafeVerifyPIN = uchar_vector(apduSafeVerifyPIN);
    std::cout << "SafeVerifyPIN APDU[" << vApduSafeVerifyPIN.size() << "]: " << apduSafeVerifyPIN << std::endl;
    JUB_FreeMemory(apduSafeVerifyPIN);

    // Verify PIN Reponse /////////////////////////////////////////////////////////////
    //    [COMM] RECV 8
    //    ------------------------------------------------
    //    E5 63 FA 68 75 7E 74 64  98 E1 78 D5 21 F9 B9 6D
    //    E9 8F 9E 4D 49 D6 DA 01  90 00
    //    No error
    //    response matches with expectation
    //    elapsed 24.000 ms
    //    ++++++++++++++++++++++++++++++++++++++++++++++++
    apduResponse = (JUB_CHAR_PTR)"0F9AD49F854DE7558709191CF4F1B7E18DE97499B1A77A209000";
    rv = JUB_GPC_ParseSafeAPDUResponse(apduResponse, &wRet, &response);
    std::cout << "JUB_GPC_ParseSafeAPDUResponse return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }
    vResp.clear();
    vResp = uchar_vector(response);
    std::cout << "SafeVerifyPIN APDU Resp[" << wRet << "]" << std::endl;
    std::cout << "SafeVerifyPIN APDU Resp[" << vResp.size() << "]: " << response << std::endl;
    JUB_FreeMemory(apduResponse);
    JUB_FreeMemory(response);

    // 6. Finalize ///////////////////////////////////////////////////////////////////////
    // JUB_GPC_Finalize() must be called when
    //    the channel is ready to be closed,
    //    or when the NFC device is disconnected,
    //    or after '00 A4 04 00',
    //    and then MUST reopen the secure channel if you want to use it again.
    rv = JUB_GPC_Finalize();
    std::cout << "JUB_GPC_Finalize return " << rv << std::endl;
    if (JUBR_OK != rv) {
        return ;
    }
}


void scp11_struct_test(const char* json_file) {

    Json::Value root = readJSON(json_file);

    //7f2181d8931042584e46433230303532353030303031420d6a75626974657277616c6c65745f200d6a75626974657277616c6c65749501825f2504202005255f24042025052453007f4946b0410479704bdb2d3da2e547eb6de66e0073f6e61ae32076af007973b5fa1dbe07e0ef38bd84d85f1fe1e1410ff743e659691b36361c76bee2fac44fd88825759268cef001005f37483046022100b076674c9f0ea1ddee84517e2a53cb392ac2c8b25ca3a7d56558570a051737020221008a982e267ffcef5309a272ea492be489a233381c477e8803034a8f6789f2bbd9
    //7f21 81d8
    //93   10 42584e46433230303532353030303031
    //42   0d 6a75626974657277616c6c6574
    //5f20 0d 6a75626974657277616c6c6574
    //95   01 82
    //5f25 04 20200525
    //5f24 04 20250524
    //53   00
    //7f49 46
    //        b0 41
    //        0479704bdb2d3da2e547eb6de66e0073f6e61ae32076af007973b5fa1dbe07e0ef38bd84d85f1fe1e1410ff743e659691b36361c76bee2fac44fd88825759268ce
    //        f0 01 00
    //5f37 48 3046022100b076674c9f0ea1ddee84517e2a53cb392ac2c8b25ca3a7d56558570a051737020221008a982e267ffcef5309a272ea492be489a233381c477e8803034a8f6789f2bbd9

    //7F21 81E8
    //93   10 434552545F4150505F45434B41303031 - Certificate Serial Number(18)
    //42   0D 6A75626974657277616C6C6574   - CA-KLOC (or KA-KLOC) Identifier(15)
    //5F20 0D 6A75626974657277616C6C6574   - Subject Identifier(16)
    //95   02 0080                         - Key Usage(4) Key agreement
    //5F25 04 20200525                     - Effective Date (YYYYMMDD, O BCD format)(7)
    //5F24 04 20250524                     - Expiration Date (YYYYMMDD, BCD M format)(7)
    //53   00                              - Discretionary Data(2)
    //BF20 0E EF0C8D0A82018202820382048205 - Restrictions under SCP11c(17)
    //7F49 46                              - Public Key(+3)
    //        B0 41 048FD3FAB3907C5CC8CD193EB2B653EA179115B7F305C9E21DE6D29C0736A3B82025B219F24BDA86D80F5AE262521E124F4C6691A0C47B1FB72D95895E9312CB0D           - public_key_q(67)
    //        F0 01 00                       - key_parameter_reference(3)
    //5F37 46 304402204D75EAA2F09604A9597DA905D680EB619B8ADCF080E5AD6950E1DBF26195C9E2022067649AFB4A8BC380B382520499C6F2BB350A8519B0ECDBE0B7374AA898826D0E(73)
    char* p = (char*)root["SCP11c"]["OCE"][0][0].asCString();
    uchar_vector vOCECert(p);
    scp11_crt oce_crt(vOCECert);
    if (!oce_crt.decode()) {
        std::cout << "scp11_crt::decode error!" << std::endl;
    }
    uint8_t sd_pub_key[65] = {0x00,};
    std::copy(oce_crt.pk.q.value.begin(), oce_crt.pk.q.value.end(), std::begin(sd_pub_key));

    std::cout << "crt.tbs["         << oce_crt.tbs.value.size() << "]: " << uchar_vector(oce_crt.tbs.value).getHex() << std::endl;
    std::cout << "crt.serial["      << oce_crt.serial.value.size() << "]: " << uchar_vector(oce_crt.serial.value).getCharsAsString() << std::endl;
    std::cout << "crt.cakloc_id ["  << oce_crt.cakloc_id.value.size() << "]:  " << uchar_vector(oce_crt.cakloc_id.value).getCharsAsString() << std::endl;
    std::cout << "crt.subject_id["  << oce_crt.subject_id.value.size() << "]: " << uchar_vector(oce_crt.subject_id.value).getCharsAsString() << std::endl;
    std::cout << "crt.valid_from["  << oce_crt.valid_from.value.size() << "]: " << uchar_vector(oce_crt.valid_from.value).getHex() << std::endl;
    std::cout << "crt.valid_to  ["  << oce_crt.valid_to.value.size() << "]: " << uchar_vector(oce_crt.valid_to.value).getHex() << std::endl;
    std::cout << "crt.key_usage: "  << oce_crt.key_usage << std::endl;
    std::cout << "crt.pk.q["        << oce_crt.pk.q.value.size() << "]: " << uchar_vector(oce_crt.pk.q.value).getHex() << std::endl;
    std::cout << "crt.pk.param["    << oce_crt.pk.param.value.size() << "]: " << uchar_vector(oce_crt.pk.param.value).getHex() << std::endl;
    std::cout << "crt.sig["         << oce_crt.sig.value.size() << "]: " << uchar_vector(oce_crt.sig.value).getHex() << std::endl;

    int rv = -1;

    const curve_info *curi = get_curve_by_name(NIST256P1_NAME);//verify sign
    if(nullptr == curi) {
        return ;
    }

    // OCE key pair(SK.OCE.ECKA, PK.OCE.ECKA)
    unsigned char oce_priv_key[32] = {0x00,};
    uchar_vector privKey((char*)root["SCP11c"]["OCE"][1][2].asCString());
    std::copy(privKey.begin(), privKey.end(), std::begin(oce_priv_key));
    unsigned char oce_pub_key[65] = {0x00,};
    uchar_vector pubKey((char*)root["SCP11c"]["OCE"][1][1].asCString());
    std::copy(pubKey.begin(), pubKey.end(), std::begin(oce_pub_key));
//    ecdsa_get_public_key65(curi->params, oce_priv_key, oce_pub_key);

    // OCE generates ephemeral key pair(eSK.OCE.ECKA, ePK.OCE.ECKA)
    unsigned char oce_e_priv_key[32] = {0x00,};
    uchar_vector eprivKey((char*)root["SCP11c"]["eKeyPair"][1].asCString());
    std::copy(eprivKey.begin(), eprivKey.end(), std::begin(oce_e_priv_key));
//    random_buffer(oce_e_priv_key, sizeof(oce_e_priv_key)/sizeof(uint8_t));
    unsigned char oce_e_pub_key[65] = {0x00,};
    uchar_vector epubKey((char*)root["SCP11c"]["eKeyPair"][0].asCString());
    std::copy(epubKey.begin(), epubKey.end(), std::begin(oce_e_pub_key));
//    ecdsa_get_public_key65(curi->params, oce_e_priv_key, oce_e_pub_key);

    // OCE calculates ShSss from PK.SD.ECKA and SK.OCE.ECKA
    SHA1_CTX sha1;
    unsigned char session_key[65] = {0x00,};
    rv = ecdh_multiply(curi->params, oce_priv_key, sd_pub_key, session_key);
    if (JUBR_OK != rv) {
        return ;
    }
    std::cout << "session_key: " << uchar_vector(session_key, sizeof(session_key)/sizeof(uint8_t)).getHex() << std::endl;
    uint8_t ShSss[20] = {0,};
    unsigned int ShSssLen = sizeof(ShSss)/sizeof(uint8_t);
    sha1_Init(&sha1);
    sha1_Update(&sha1, session_key + 1, 32);
    sha1_Final(&sha1, ShSss);
    std::cout << "ShSss: " << uchar_vector(ShSss, ShSssLen).getHex() << std::endl;

    // OCE calculates ShSes from PK.SD.ECKA and eSK.OCE.ECKASD
    memset(session_key, 0x00, sizeof(session_key)/sizeof(uint8_t));
    rv = ecdh_multiply(curi->params, oce_e_priv_key, sd_pub_key, session_key);
    if (JUBR_OK != rv) {
        return ;
    }
    std::cout << "session_key: " << uchar_vector(session_key, sizeof(session_key)/sizeof(uint8_t)).getHex() << std::endl;
    uint8_t ShSes[20] = {0,};
    unsigned int ShSesLen = sizeof(ShSes)/sizeof(uint8_t);
    sha1_Init(&sha1);
    sha1_Update(&sha1, session_key + 1, 32);
    sha1_Final(&sha1, ShSes);
    std::cout << "ShSes: " << uchar_vector(ShSes, ShSesLen).getHex() << std::endl;

    // OCE derives AES sessionkeys from ShSes and ShSss
    uint8_t z[40] = {0x00,};
    unsigned int zLen = sizeof(z)/sizeof(uint8_t);
    memcpy(z, ShSes, ShSesLen);
    memcpy(z + ShSesLen, ShSss, ShSssLen);
    // sharedInfo, keyUsage = 0x88. 以 LV 形式组织。
    uchar_vector keyUsage;
    keyUsage.push_back(0x3C);
    uchar_vector keyType;
    keyType.push_back(0x88);
    uchar_vector keyLength;
    keyLength.push_back(root["SCP11c"]["KeyLength"].asUInt());
    uchar_vector hostID((char*)root["SCP11c"]["HostID"].asCString());
    scp11_sharedInfo shInfo(keyUsage,
                            keyType,
                            keyLength,
                            hostID);
    uchar_vector sharedInfo = shInfo.encodeLV();
    std::cout << "sharedInfo: " << sharedInfo.getHex() << std::endl;
    unsigned int sharedInfoLen = (unsigned int)sharedInfo.size();
    unsigned char* pSharedInfo = new unsigned char[sharedInfoLen+1];
    memset(pSharedInfo, 0x00, sharedInfoLen+1);
    std::copy(sharedInfo.begin(), sharedInfo.end(), pSharedInfo);
    unsigned char outKey[0x10*5] = {0x00,};
    uint32_t outKeyLen = sizeof(outKey)/sizeof(unsigned char);
    outKeyLen = kdf2_sha256(z, zLen,
                            pSharedInfo, sharedInfoLen,
                            outKey, outKeyLen);
    delete [] pSharedInfo; pSharedInfo = nullptr;
    std::cout << "AES sessionkeys[" << outKeyLen <<  "]: " << uchar_vector(outKey, outKeyLen).getHex() << std::endl;
    scp11_session_key sk(uchar_vector(outKey, outKeyLen));
    if (!sk.decode()) {
        return ;
    }

    // OCE prepares MUTUAL AUTHENTICATE prepare payload

    // OCE wraps APDUs into SCP03 using AES session keys("payload")
    // OCE prepares script and resources for APK file
    // OCE transmits script to REA via AppStore
}
