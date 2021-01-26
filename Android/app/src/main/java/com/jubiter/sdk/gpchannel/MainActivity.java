package com.jubiter.sdk.gpchannel;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;

import com.jubiter.sdk.gpchannel.utils.JSONParseUtils;

import org.haobtc.onekey.card.gpchannel.GPChannelNatives;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_test:
                test();
                break;
            case R.id.btn_tlv:
                tlv_test();
                break;
            default:
                break;
        }
    }

    private void test() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                // 1. Initialize /////////////////////////////////////////////////////////////////////
                // JUB_GPC_Initialize() is called when it is ready to start the secure channel.
                int ret = GPChannelNatives.nativeGPCInitialize(JSONParseUtils.getJsonStr(MainActivity.this, "initParams.json"));
                printLog("nativeGPCInitialize: " + ret);
                if (ret != 0) {
                    return;
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
                String apduPSO = GPChannelNatives.nativeGPCBuildAPDU(0x80, 0x2A, 0x18, 0x10,
                        "7F2181E89310434552545F4150505F45434B41303031420D6A75626974657277616C6C65745F200D6A75626974657277616C6C6574950200805F2504202005255F2404202505245300BF200EEF0C8D0A820182028203820482057F4946B041048FD3FAB3907C5CC8CD193EB2B653EA179115B7F305C9E21DE6D29C0736A3B82025B219F24BDA86D80F5AE262521E124F4C6691A0C47B1FB72D95895E9312CB0DF001005F3746304402204D75EAA2F09604A9597DA905D680EB619B8ADCF080E5AD6950E1DBF26195C9E2022067649AFB4A8BC380B382520499C6F2BB350A8519B0ECDBE0B7374AA898826D0E");
                if (TextUtils.isEmpty(apduPSO)) {
                    printLog("nativeGPCBuildAPDU error:" + GPChannelNatives.nativeGetErrorCode());
                    return;
                }
                printLog("nativeGPCBuildAPDU: " + apduPSO);

                // MutualAuthenticate: 80 82 18 15 ////////////////////////////////////////////////
                String mutualAuthData = GPChannelNatives.nativeGPCBuildMutualAuthData();
                if (TextUtils.isEmpty(mutualAuthData)) {
                    printLog("nativeGPCBuildMutualAuthData error:" + GPChannelNatives.nativeGetErrorCode());
                    return;
                }
                printLog("nativeGPCBuildMutualAuthData: " + mutualAuthData);

                //    ------------------------------------------------
                //    80 82 18 15 5d
                //    a6 17 90 02 11 07 95 01  3c 80 01 88 81 01 10 84
                //    08 80 80 80 80 80 80 80  80 5f 49 41 04 57 6f 1a
                //    98 8d c0 0a d9 b5 53 3b  16 59 c7 94 35 61 02 19
                //    da 2a b3 7b 43 d6 92 dc  13 39 cd c1 31 f1 20 50
                //    83 53 f6 0b 9a d7 dc 5e  00 12 15 f5 8c 00 57 cd
                //    23 37 5e fe 96 1d 77 72  fe 58 16 23 20
                //    ==================== EXPECT ====================
                String apduMA = GPChannelNatives.nativeGPCBuildAPDU(0x80, 0x82, 0x18, 0x15, mutualAuthData);
                if (TextUtils.isEmpty(apduMA)) {
                    printLog("nativeGPCBuildAPDU error:" + GPChannelNatives.nativeGetErrorCode());
                    return;
                }
                printLog("nativeGPCBuildAPDU: " + apduMA);

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

                String res = GPChannelNatives.nativeGPCParseAPDUResponse("5F49410479704BDB2D3DA2E547EB6DE66E0073F6E61AE32076AF007973B5FA1DBE07E0EF38BD84D85F1FE1E1410FF743E659691B36361C76BEE2FAC44FD88825759268CE8610645BF0A0FFE71D300BCD07D89C5B20A99000");
                if (TextUtils.isEmpty(res)) {
                    printLog("nativeGPCParseAPDUResponse error:" + GPChannelNatives.nativeGetErrorCode());
                    return;
                }
                printLog("nativeGPCParseAPDUResponse: " + res);

                // 3. OpenSecureChannel //////////////////////////////////////////////////////////////
                ret = GPChannelNatives.nativeGPCOpenSecureChannel("5F49410479704BDB2D3DA2E547EB6DE66E0073F6E61AE32076AF007973B5FA1DBE07E0EF38BD84D85F1FE1E1410FF743E659691B36361C76BEE2FAC44FD88825759268CE8610645BF0A0FFE71D300BCD07D89C5B20A9");
                printLog("nativeGPCOpenSecureChannel: " + ret);
                if (ret != 0) {
                    return;
                }

                // 4. Secure channel APDU /////////////////////////////////////////////////////////
                // JUB_GPC_BuildSafeAPDU() and JUB_GPC_ParseSafeAPDUResponse() MUST be called in pairs.
                // Non-ciphertext APDU can be interspersed between ciphertext APDUs in the channel.
                // Verify PIN: 80 20 00 00 ////////////////////////////////////////////////////////
                //    ------------------------------------------------
                //    84 20 00 00 18
                //    4b 25 1c 59 21 0b 67 4d  ee 52 c5 80 d8 ef 01 77
                //    cd b6 7e f6 05 bf 67 ff
                //    ==================== EXPECT ====================

                String apduSafeVerifyPIN = GPChannelNatives.nativeGPCBuildSafeAPDU(0x80, 0x20, 0x00, 0x00, "0435353535");
                if (TextUtils.isEmpty(apduSafeVerifyPIN)) {
                    printLog("nativeGPCBuildSafeAPDU error:" + GPChannelNatives.nativeGetErrorCode());
                    return;
                }
                printLog("nativeGPCBuildSafeAPDU: " + apduSafeVerifyPIN);

                // Verify PIN Reponse /////////////////////////////////////////////////////////////
                //    [COMM] RECV 8
                //    ------------------------------------------------
                //    4C E5 5D EE 47 18 BC D0  01 0E AC 79 42 32 47 5C
                //    5B F4 6D 9E 0B BA 68 34  90 00
                //    No error
                //    response matches with expectation
                //    elapsed 24.000 ms
                //    ++++++++++++++++++++++++++++++++++++++++++++++++

                res = GPChannelNatives.nativeGPCParseSafeAPDUResponse("4CE55DEE4718BCD0010EAC794232475C5BF46D9E0BBA68349000");
                if (TextUtils.isEmpty(res)) {
                    printLog("nativeGPCParseSafeAPDUResponse error:" + GPChannelNatives.nativeGetErrorCode());
                    return;
                }
                printLog("nativeGPCParseSafeAPDUResponse: " + res);

                // Verify PIN: 80 20 00 00 ////////////////////////////////////////////////////////
                //    ------------------------------------------------
                //    84 20 00 00 18
                //    ee 5d 8b 0b 57 ed 45 5f  03 62 b5 1b e6 f7 96 e3
                //    09 5b 9f f3 16 82 8e 34
                //    ==================== EXPECT ====================
                apduSafeVerifyPIN = GPChannelNatives.nativeGPCBuildSafeAPDU(0x80, 0x20, 0x00, 0x00, "0435353535");
                if (TextUtils.isEmpty(apduSafeVerifyPIN)) {
                    printLog("nativeGPCBuildSafeAPDU error:" + GPChannelNatives.nativeGetErrorCode());
                    return;
                }
                printLog("nativeGPCBuildSafeAPDU: " + apduSafeVerifyPIN);

                // Verify PIN Reponse /////////////////////////////////////////////////////////////
                //    [COMM] RECV 8
                //    ------------------------------------------------
                //    E5 63 FA 68 75 7E 74 64  98 E1 78 D5 21 F9 B9 6D
                //    E9 8F 9E 4D 49 D6 DA 01  90 00
                //    No error
                //    response matches with expectation
                //    elapsed 24.000 ms
                //    ++++++++++++++++++++++++++++++++++++++++++++++++
                res = GPChannelNatives.nativeGPCParseSafeAPDUResponse("0F9AD49F854DE7558709191CF4F1B7E18DE97499B1A77A209000");
                if (TextUtils.isEmpty(res)) {
                    printLog("nativeGPCParseSafeAPDUResponse error:" + GPChannelNatives.nativeGetErrorCode());
                    return;
                }
                printLog("nativeGPCParseSafeAPDUResponse: " + res);

                // 5. Finalize ///////////////////////////////////////////////////////////////////////
                // JUB_GPC_Finalize() must be called when
                //    the channel is ready to be closed,
                //    or when the NFC device is disconnected,
                //    or after '00 A4 04 00',
                //    and then MUST reopen the secure channel if you want to use it again.
                ret = GPChannelNatives.nativeGPCFinalize();

                printLog("nativeGPCFinalize: " + ret);
            }
        }).start();
    }


    private void tlv_test() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                // GET DEVICE CERTIFICATE : 80 CA BF 21 //////////////////////////////////////////////
                String res = GPChannelNatives.nativeGPCTLVDecode("bf2181dc7f2181d8931042584e46433230303532353030303031420d6a75626974657277616c6c65745f200d6a75626974657277616c6c65749501825f2504202005255f24042025052453007f4946b0410479704bdb2d3da2e547eb6de66e0073f6e61ae32076af007973b5fa1dbe07e0ef38bd84d85f1fe1e1410ff743e659691b36361c76bee2fac44fd88825759268cef001005f37483046022100b076674c9f0ea1ddee84517e2a53cb392ac2c8b25ca3a7d56558570a051737020221008a982e267ffcef5309a272ea492be489a233381c477e8803034a8f6789f2bbd9");
                if (TextUtils.isEmpty(res)) {
                    printLog("nativeGPCTLVDecode error:" + GPChannelNatives.nativeGetErrorCode());
                    return;
                }
                printLog(res);
            }
        }).start();
    }


    private void printLog(String msg) {
        Log.d("GPChannel", msg);
    }
}