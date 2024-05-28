cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

project(fty-alert-flexible
    VERSION 1.0.0
    DESCRIPTION "fty-alert-flexible"
)

find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR})

########################################################################################################################

add_subdirectory(lib)
add_subdirectory(agent)

## agent configuration
## https://cmake.org/cmake/help/v3.0/module/GNUInstallDirs.html

## Important note: no rule template installation here
## even if we have some templates in lib/tests/selftest-ro/rules/templates
## *all* flexible rule templates are owened by fty-alert-engine repo (src/rule_template/)
## and installed in /usr/share/bios/fty-autoconfig

set(AGENT_USER "bios")
set(AGENT_ETC_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME}")
set(AGENT_ETC_FTY_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/fty/${PROJECT_NAME}")
set(AGENT_VAR_DIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/fty/${PROJECT_NAME}")
set(AGENT_SHARE_DIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}/${PROJECT_NAME}")
set(AGENT_AUDITLOG_DIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log/app-audit")

# alert audit-log receipt -> var/log/app-audit
install(DIRECTORY DESTINATION ${AGENT_AUDITLOG_DIR})

## .conf file -> lib/tmpfiles.d/
configure_file("${PROJECT_SOURCE_DIR}/resources/${PROJECT_NAME}.conf" "${PROJECT_BINARY_DIR}/resources/${PROJECT_NAME}.conf" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/resources/${PROJECT_NAME}.conf" DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/tmpfiles.d/")

# cfg -> etc
configure_file("${PROJECT_SOURCE_DIR}/resources/fty-alert-flexible.cfg.in" "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible.cfg" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible.cfg" DESTINATION ${AGENT_ETC_DIR})
install(DIRECTORY DESTINATION ${AGENT_VAR_DIR}/rules)

# service -> lib/systemd/system
configure_file("${PROJECT_SOURCE_DIR}/resources/fty-alert-flexible.service.in" "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible.service" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible.service" DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/)
