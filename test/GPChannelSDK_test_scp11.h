//
//  GPChannelSDK_test_scp11.h
//  GPChannelSDKTest
//
//  Created by panmin on 2020/7/9.
//  Copyright © 2020 JuBiter. All rights reserved.
//

#ifndef GPChannelSDK_test_scp11_h
#define GPChannelSDK_test_scp11_h

#include <stdio.h>
#include <iostream>     // std::cout
#include "../../include/GPChannelSDK.h"

using namespace std;

void scp11_tlv_test();
void scp11_process_sample(const char* json_file);
void scp11_struct_test(const char* json_file);

#endif /* GPChannelSDK_test_scp11_h */
