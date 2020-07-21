project(gpchannelNDK)

cmake_minimum_required(VERSION 3.6.0)

message("===============================>>> ndk")

# **************************************************************************************************
#                               引入相关头文件
# 注：因为是分开编译且涉及相互调用，所以需要引入其他库模块中的头文件
# **************************************************************************************************
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utils)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/GPChannel/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utils/jsoncpp/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utils/mSIGNA/stdutils)


# **************************************************************************************************
#                      查找指定目录下的所有源文件，并将其存入指定变量中
# **************************************************************************************************

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src SRC_LIST)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/utils SRC_LIST)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/utils/jsoncpp/src/lib_json SRC_LIST)


# **************************************************************************************************
#                                添加其他预构建库（第三方库）
# **************************************************************************************************

find_library(libLog
             log
)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/GPChannel/src/${ANDROID_ABI})


# **************************************************************************************************
#                                        生成动态库
# **************************************************************************************************

add_library(
            gpchannelNDK
            SHARED
            ${SRC_LIST}
)



# **************************************************************************************************
#                                        链接所有相关库
# 切记链接日志库，否则编译报错 undefined reference to '__android_log_print'
# **************************************************************************************************

target_link_libraries(
                      gpchannelNDK
                      JUB_GPC_APDU_SDK
                      TrezorCrypto
                      ${libLog}
)
