//
//  GPChannelSDK_main.cpp
//  GPChannelSDKTest
//
//  Created by Pan Min on 2020/7/9.
//  Copyright © 2020 JuBiter. All rights reserved.
//

#include "GPChannelSDK_main.h"
#include "GPChannelSDK_test_scp11.h"

using namespace std;

std::string GetErrMsg(JUB_RV rv) {

    std::string errMsg;
    switch (rv) {
        case JUBR_OK:                   { errMsg = "JUBR_OK"; break; }
        case JUBR_ERROR:                { errMsg = "JUBR_ERROR"; break; }
        case JUBR_HOST_MEMORY:          { errMsg = "JUBR_HOST_MEMORY"; break; }
        case JUBR_ARGUMENTS_BAD:        { errMsg = "JUBR_ARGUMENTS_BAD"; break; }
        case JUBR_IMPL_NOT_SUPPORT:     { errMsg = "JUBR_IMPL_NOT_SUPPORT"; break; }
        case JUBR_MEMORY_NULL_PTR:      { errMsg = "JUBR_MEMORY_NULL_PTR"; break; }
        case JUBR_INVALID_MEMORY_PTR:   { errMsg = "JUBR_INVALID_MEMORY_PTR"; break; }
        case JUBR_REPEAT_MEMORY_PTR:    { errMsg = "JUBR_REPEAT_MEMORY_PTR"; break; }
        case JUBR_BUFFER_TOO_SMALL:     { errMsg = "JUBR_BUFFER_TOO_SMALL"; break; }

        default:                        { errMsg = "UNKNOWN ERROR."; break; }
    }

    return errMsg;
}

void error_exit(const char* message) {

    cout << message << endl;
    cout << "press any key to exit" << endl;
    char str[9] = { 0, };
    cin >> str;
    exit(0);
}

Json::Value readJSON(const char* json_file) {
    Json::CharReaderBuilder builder;
    Json::Value root;
    ifstream in(json_file, ios::binary);
    if (!in.is_open()) {
        error_exit("Error opening json file\n");
    }
    JSONCPP_STRING errs;
    if (!parseFromStream(builder, in, &root, &errs)) {
        error_exit("Error parse json file\n");
    }

    return root;
}

int main() {

    while(true) {
        cout << "--------------------------------------" << endl;
        cout << "|******* Jubiter Wallet Test ********|" << endl;
        cout << "|  1. scp11_tlv_test.                |" << endl;
        cout << "|  2. scp11_process_test.            |" << endl;
        cout << "| 99. scp11_struct_test.             |" << endl;
        cout << "|  0. exit.                          |" << endl;
        cout << "--------------------------------------" << endl;
        cout << "* Please enter your choice:" << endl;

        int choice = 0;
        cin >> choice;
        switch (choice) {
            case  1:
                scp11_tlv_test();
                break;
            case  2:
                scp11_process_sample("settings/42584E46433230303532353030303031_apk.settings");
                break;
            case 99:
                scp11_struct_test("settings/42584E46433230303532353030303031_apk.settings");
//                scp11_struct_test("settings/42584E46433230303532353030303032_apk.settings");
                break;
            case 0:
                exit(0);
            default:
                continue;
        }
    }

    return 0;
}
