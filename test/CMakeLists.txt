cmake_minimum_required(VERSION 3.10.0)
project(pam_tester VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)

find_path(PAM_INCLUDE_DIR security/pam_appl.h)
find_library(PAM_LIBRARY pam)

if(NOT PAM_INCLUDE_DIR OR NOT PAM_LIBRARY)
    message(FATAL_ERROR "Could not find PAM")
endif()

add_executable(pam_tester main.c)
target_include_directories(pam_tester PRIVATE ${PAM_INCLUDE_DIR})
target_link_libraries(pam_tester PRIVATE ${PAM_LIBRARY})

install(TARGETS pam_tester 
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)