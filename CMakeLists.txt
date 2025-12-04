cmake_minimum_required(VERSION 3.1.0...3.10 FATAL_ERROR)
project(pbotp)

if(POLICY CMP0063)
  cmake_policy(SET CMP0063 NEW)
endif()

option(BUILD_PAM_TEST "build PAM test harness")

add_compile_options(
	-Wall
	-Wextra
	-Wshadow
	-Wno-unused-parameter
	-Wmissing-noreturn
	-Wmissing-prototypes
	-Wstrict-prototypes
)

set(COMMON_FILES
	base64.c
	challenge.c
	hmac.c
	sha256.c
	tweetnacl.c
	utils.c
)

find_package(PkgConfig)
if(PkgConfig_FOUND)
	pkg_search_module(QRENCODE libqrencode)
	if(QRENCODE_FOUND)
		add_compile_definitions(HAVE_QR)
		set(COMMON_FILES ${COMMON_FILES} qr.c)
	else()
		message("libqrencode not found, not building QR code support")
	endif()

else()
	message("PkgConfig not found, cannot detect QR code support")
endif()

include(GNUInstallDirs)

add_executable(genkey base64.c tweetnacl.c utils.c genkey.c)

add_library(pam_pbotp SHARED pam_pbotp.c ${COMMON_FILES})
set_target_properties(pam_pbotp PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(pam_pbotp PROPERTIES PREFIX "")
target_link_libraries(pam_pbotp pam)

if(QRENCODE_FOUND)
	target_link_libraries(pam_pbotp ${QRENCODE_LIBRARIES})
	target_include_directories(pam_pbotp PRIVATE ${QRENCODE_INCLUDE_DIRS})
endif()

if(BUILD_PAM_TEST)
	add_executable(pam-test pam-test.c pam_pbotp.c ${COMMON_FILES})
	if(QRENCODE_FOUND)
		target_link_libraries(pam-test ${QRENCODE_LIBRARIES})
		target_include_directories(pam-test PRIVATE ${QRENCODE_INCLUDE_DIRS})
	endif()
endif()

include(CTest)
if(BUILD_TESTING)
	add_subdirectory(test)
endif()

install(TARGETS pam_pbotp LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/security/")
