find_package(PkgConfig REQUIRED)

pkg_search_module(CMOCKA REQUIRED cmocka)

add_compile_options(
	-Wall
	-Wextra
	-Wshadow
	-Wno-unused-parameter
	-Wmissing-noreturn
	-Wmissing-prototypes
	-Wstrict-prototypes

	-fsanitize=undefined
	-fsanitize=address
)

link_libraries(-fsanitize=address -fsanitize=undefined)

add_compile_definitions(TESTING)

add_executable(base64 base64.c ../base64.c)
target_include_directories(base64 PRIVATE ${PROJECT_SOURCE_DIR} ${CURRENT_SOURCE_DIR} ${CMOCKA_INCLUDES})
target_link_libraries(base64 PRIVATE ${CMOCKA_LIBRARIES})
add_test(base64 base64)

add_executable(sha256 sha256.c ../sha256.c)
target_include_directories(sha256 PRIVATE ${PROJECT_SOURCE_DIR} ${CURRENT_SOURCE_DIR} ${CMOCKA_INCLUDES})
target_link_libraries(sha256 PRIVATE ${CMOCKA_LIBRARIES})
add_test(sha256 sha256)

add_executable(hmac hmac.c ../hmac.c ../sha256.c ../utils.c)
target_include_directories(hmac PRIVATE ${PROJECT_SOURCE_DIR} ${CURRENT_SOURCE_DIR} ${CMOCKA_INCLUDES})
target_link_libraries(hmac PRIVATE ${CMOCKA_LIBRARIES})
add_test(hmac hmac)

add_executable(challenge challenge.c ../challenge.c ../sha256.c ../hmac.c ../tweetnacl.c ../utils.c)
target_include_directories(challenge PRIVATE ${PROJECT_SOURCE_DIR} ${CURRENT_SOURCE_DIR} ${CMOCKA_INCLUDES})
target_link_libraries(challenge PRIVATE ${CMOCKA_LIBRARIES})
add_test(challenge challenge)
