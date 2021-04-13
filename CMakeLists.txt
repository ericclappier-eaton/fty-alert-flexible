cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

##############################################################################################################

project(fty-alert-flexible VERSION 1.0.0)

########################################################################################################################

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
set(AGENT_ETC_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/fty/${PROJECT_NAME}")
set(AGENT_VAR_DIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/fty/${PROJECT_NAME}")
set(AGENT_SHARE_DIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}/${PROJECT_NAME}")
set(AGENT_AUDITLOG_DIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log/app-audit")
set(AGENT_AUDITLOG_FILE "${AGENT_AUDITLOG_DIR}/alarms-audit.log")

# alert audit-log receipt -> var/log/app-audit
install(DIRECTORY DESTINATION ${AGENT_AUDITLOG_DIR})

# cfg -> etc/fty
configure_file("${PROJECT_SOURCE_DIR}/resources/fty-alert-flexible.cfg.in" "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible.cfg" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible.cfg" DESTINATION ${AGENT_ETC_DIR})
install(DIRECTORY DESTINATION ${AGENT_VAR_DIR}/rules)

# logging conf file -> etc/fty
configure_file("${PROJECT_SOURCE_DIR}/resources/fty-alert-flexible-log.cfg.in" "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible-log.cfg" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible-log.cfg" DESTINATION ${AGENT_ETC_DIR})

# service -> lib/systemd/system
configure_file("${PROJECT_SOURCE_DIR}/resources/fty-alert-flexible.service.in" "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible.service" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/resources/fty-alert-flexible.service" DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/)
