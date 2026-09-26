# SPDX-License-Identifier: GPL-2.0-only
cmake_minimum_required(VERSION 3.13)
project(ipad C)

set(CMAKE_C_STANDARD 99)
# warnings are errors while developing; a distribution build (a compiler newer
# than the one this was written against) turns that off with -DIPAD_WERROR=OFF
option(IPAD_WERROR "treat warnings as errors" ON)
add_compile_options(-Wall -Wextra)
if(IPAD_WERROR)
	add_compile_options(-Werror)
endif()

# mbedTLS is built in, statically: RSP needs brainpoolP256r1, which the
# distribution's shared mbedTLS need not have enabled (OpenWrt's does not by
# default), and the binary should not depend on how that library is set up.
option(IPAD_BUNDLED_MBEDTLS "build mbedTLS from source (static)" ON)
set(IPAD_MBEDTLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls-3.6.7" CACHE PATH "mbedTLS source tree")

if(IPAD_BUNDLED_MBEDTLS)
	if(NOT EXISTS "${IPAD_MBEDTLS_DIR}/CMakeLists.txt")
		message(FATAL_ERROR "no mbedTLS source in ${IPAD_MBEDTLS_DIR}: run tools/fetch-mbedtls.sh or set IPAD_MBEDTLS_DIR")
	endif()
	set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
	set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
	set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
	# the release tarball carries its generated sources; never regenerate them
	# (that would want perl/python on the build host, for the same bytes)
	set(GEN_FILES OFF CACHE BOOL "" FORCE)
	add_subdirectory(${IPAD_MBEDTLS_DIR} ${CMAKE_CURRENT_BINARY_DIR}/mbedtls EXCLUDE_FROM_ALL)
endif()

add_library(ipadcore STATIC src/bundle.c src/der.c src/hex.c src/crypto.c src/connectivity.c src/card.c src/http.c src/emu.c src/emu_state.c src/euicc.c src/ipa.c src/host.c)
target_include_directories(ipadcore PUBLIC src)
target_link_libraries(ipadcore PUBLIC mbedtls mbedx509 mbedcrypto)

add_executable(ipad src/main.c)
target_link_libraries(ipad ipadcore)
install(TARGETS ipad RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
	add_library(testsupport STATIC tests/simcard.c tests/fake22.c tests/eimpkg.c)
	target_link_libraries(testsupport ipadcore)
	foreach(t bundle der crypto connectivity card http emu ipa)
		add_executable(test_${t} tests/test_${t}.c)
		target_include_directories(test_${t} PRIVATE tests)
		target_link_libraries(test_${t} testsupport ipadcore)
		target_compile_definitions(test_${t} PRIVATE FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures"
			TESTS="${CMAKE_CURRENT_SOURCE_DIR}/tests")
		add_test(NAME ${t} COMMAND test_${t})
	endforeach()
	# the real binary over the stdio protocol, card simulated by the host
	add_executable(hostsim tests/hostsim.c)
	target_include_directories(hostsim PRIVATE tests)
	target_link_libraries(hostsim testsupport ipadcore)
	add_test(NAME cli COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli.sh ${CMAKE_CURRENT_BINARY_DIR})
endif()
