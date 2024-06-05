cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

########################################################################################################################

etn_target(static ${PROJECT_NAME}-lib
    SOURCES
        flexible_alert.cc
        flexible_alert.h
        audit_log.cc
        audit_log.h
        rule.cc
        rule.h
        asset_info.cc
        asset_info.h
    USES_PRIVATE
        cxxtools
        lua5.4
        czmq
        mlm
        fty_shm
        fty_proto
        fty_common_logging
        fty_common
    PRIVATE
)

########################################################################################################################

etn_test_target(${PROJECT_NAME}-lib
    CONFIGS
        tests/selftest-ro/*
    SOURCES
        tests/main.cpp
        tests/rule.cpp
        tests/flexible_alert.cpp
    PREPROCESSOR
        -DCATCH_CONFIG_FAST_COMPILE
    SUBDIR
        tests
)

########################################################################################################################
