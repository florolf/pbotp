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

add_executable(blake2s blake2s.c ../blake2s.c)
target_include_directories(blake2s PRIVATE ${PROJECT_SOURCE_DIR} ${CURRENT_SOURCE_DIR} ${CMOCKA_INCLUDES})
target_link_libraries(blake2s PRIVATE ${CMOCKA_LIBRARIES})
add_test(blake2s blake2s)

add_executable(challenge challenge.c ../challenge.c ../blake2s.c ../tweetnacl.c ../utils.c)
target_include_directories(challenge PRIVATE ${PROJECT_SOURCE_DIR} ${CURRENT_SOURCE_DIR} ${CMOCKA_INCLUDES})
target_link_libraries(challenge PRIVATE ${CMOCKA_LIBRARIES})
add_test(challenge challenge)
