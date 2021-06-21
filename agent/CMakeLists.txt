cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

########################################################################################################################

etn_target(exe ${PROJECT_NAME}
    SOURCES
        src/fty-alert-flexible.cc
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib/src
    USES
        czmq
        fty_proto
        fty_common_mlm
        fty_common_logging
    USES_PRIVATE
        ${PROJECT_NAME}-lib
)

########################################################################################################################
