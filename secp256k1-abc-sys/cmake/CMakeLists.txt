cmake_minimum_required(VERSION 3.5)

project(secp256k1-abc)

set(CMAKE_MODULE_PATH
	${CMAKE_MODULE_PATH}
	${CMAKE_CURRENT_SOURCE_DIR}/modules
)
# always use builtin
set(CMAKE_DISABLE_FIND_PACKAGE_GMP TRUE)

include(AddCompilerFlags)

add_subdirectory(secp256k1)
