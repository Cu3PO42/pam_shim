cmake_minimum_required(VERSION 3.10.0)
project(pam_shim VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)

find_library(PAM_LIBRARY pam)
if(NOT PAM_LIBRARY)
    message(FATAL_ERROR "Could not find PAM")
endif()

add_library(shared OBJECT src/shared/message.c src/shared/buffered_fd.c src/shared/util.c)
target_include_directories(shared PRIVATE ${CMAKE_SOURCE_DIR}/include)

add_executable(pam_shim_server src/server/server.c)
target_link_libraries(pam_shim_server PRIVATE ${PAM_LIBRARY} shared)
target_include_directories(pam_shim_server PRIVATE ${CMAKE_SOURCE_DIR}/include)

add_library(libpam SHARED src/lib/lib.c src/lib/remote.c)
target_link_libraries(libpam PRIVATE shared)
target_include_directories(libpam PRIVATE ${CMAKE_SOURCE_DIR}/include)
set_target_properties(libpam PROPERTIES OUTPUT_NAME "pam" SOVERSION 0)
target_link_options(libpam PRIVATE "-Wl,--version-script=${CMAKE_SOURCE_DIR}/pam_shim.map")
if (PAM_SHIM_DEFAULT_SERVER)
    target_compile_definitions(libpam PRIVATE PAM_SHIM_DEFAULT_SERVER="${PAM_SHIM_DEFAULT_SERVER}")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(shared PRIVATE -Oz -flto)
    target_compile_options(pam_shim_server PRIVATE -Oz -flto)
    target_link_options(pam_shim_server PRIVATE -Oz -flto)
    target_compile_options(libpam PRIVATE -Oz -flto)
    target_link_options(libpam PRIVATE -Oz -flto)
endif()

install(TARGETS pam_shim_server libpam
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/security/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/security
    FILES_MATCHING PATTERN "*.h"
)