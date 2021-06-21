cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

########################################################################################################################

etn_target(static ${PROJECT_NAME}-lib
    SOURCES
        flexible_alert.cc
        flexible_alert.h
        fty_alert_flexible_audit_log.cc
        fty_alert_flexible_audit_log.h
        rule.cc
        rule.h
        vsjson.cc
        vsjson.h
    USES_PRIVATE
        lua5.1
        czmq
        mlm
        fty_shm
        fty_proto
        fty_common_logging
    PRIVATE
)

########################################################################################################################

etn_test_target(${PROJECT_NAME}-lib
    CONFIGS
        tests/selftest-ro/*
    SOURCES
        tests/flexible_alert.cpp
        tests/main.cpp
        tests/rule.cpp
    PREPROCESSOR
        -DCATCH_CONFIG_FAST_COMPILE
    SUBDIR
        tests
)

########################################################################################################################
