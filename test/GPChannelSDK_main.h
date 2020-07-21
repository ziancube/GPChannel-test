//
//  GPChannelSDK_main.h
//  GPChannelSDKTest
//
//  Created by Pan Min on 2020/7/9.
//  Copyright © 2020 JuBiter. All rights reserved.
//

#ifndef GPChannelSDK_main_h
#define GPChannelSDK_main_h

#include "GPChannelSDK.h"

#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstring>
#include <thread>
#include <json/json.h>
using namespace std;

std::string GetErrMsg(JUB_RV rv);
void error_exit(const char* message);
Json::Value readJSON(const char* json_file);

#endif /* GPChannelSDK_main_h */
