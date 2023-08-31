# set the minimum cmake to 3.24 to be able to use FIND_PACKAGE_ARGS
cmake_minimum_required(VERSION 3.24)
# include some local cmake configuration file
include(local_conf.cmake OPTIONAL)

# set the CMake project properties
project(ShimmerppExamples VERSION 1.0 DESCRIPTION "Console applications to create outputs" LANGUAGES CXX)

# set the build type defaults
set(default_build_type "Release")
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
		STRING "Choose the type of build." FORCE)
	# Set the possible values of build type for cmake-gui
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
		"Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# set cmake variables
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
include(GNUInstallDirs)

include(FetchContent)
# Get the library that sends blocks to the Stardust nodes
# This will check if the library is installed first, if not download it from GitHub and compile it
FetchContent_Declare(
	qclient
	GIT_REPOSITORY https://github.com/EddyTheCo/Qclient-IOTA.git
	GIT_TAG v0.2.2
	FIND_PACKAGE_ARGS 0 CONFIG
	)
FetchContent_MakeAvailable(qclient)

# Get the library that connects to the event API of the nodes https://wiki.iota.org/shimmer/tips/tips/TIP-0028/
FetchContent_Declare(
	qclientMQTT
	GIT_REPOSITORY https://github.com/EddyTheCo/QclientMqtt-IOTA.git
	GIT_TAG v0.2.2
	FIND_PACKAGE_ARGS 0 CONFIG
	)
FetchContent_MakeAvailable(qclientMQTT)

# Get the library that consume outputs(prepare the Inputs,Inputs Commitment, Unlocks) of certain address.
# This will check if the library is installed first, if not download it from GitHub and compile it
FetchContent_Declare(
	qaddr_bundle
	GIT_REPOSITORY https://github.com/EddyTheCo/QAddrBundle.git
	GIT_TAG v0.2.2
	FIND_PACKAGE_ARGS 0 CONFIG
	)
FetchContent_MakeAvailable(qaddr_bundle)


# Get the library for  generating pair keys from a master key for ed25519 curve types.
# This will check if the library is installed first, if not download it from GitHub and compile it
FetchContent_Declare(
	qslip10
	GIT_REPOSITORY https://github.com/EddyTheCo/Qslip10.git
	GIT_TAG v0.0.1
	FIND_PACKAGE_ARGS 0 CONFIG
	)
FetchContent_MakeAvailable(qslip10)

# Get the library for elliptic curve signature scheme Edwards-curve Digital Signature Algorithm (EdDSA)..
# This will check if the library is installed first, if not download it from GitHub and compile it
FetchContent_Declare(
	qed25519
	GIT_REPOSITORY https://github.com/EddyTheCo/Qed25519.git
	GIT_TAG v0.0.1
	)
FetchContent_MakeAvailable(qed25519)


# Find Core and Network Qt6 components
find_package(Qt6 COMPONENTS Core Network REQUIRED)

# https://doc.qt.io/qt-6/qt-standard-project-setup.html
qt_standard_project_setup()
# Iterate for all the output examples
include(CTest)
foreach(example "basic_output"
		"NFT_output"
		"alias_output"
		"foundry_output"
		)
	# Add the executable to the project
	qt_add_executable( ${example}  ${example}.cpp)
	message(STATUS "Configuring example ${example}" )
	# Link the used libraies in the executable
	target_link_libraries(${example} PRIVATE qclient qaddr_bundle qslip10 qed25519 qclientMQTT)

	set_target_properties(${example} PROPERTIES
		WIN32_EXECUTABLE ON
		MACOSX_BUNDLE ON
		)
	# Install the different targets
	install(TARGETS ${example}
		BUNDLE  DESTINATION .
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
	if (WIN32)
		add_custom_command(
			TARGET ${example} POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:${example}> $<TARGET_FILE_DIR:${example}>
			COMMAND_EXPAND_LISTS
			)
	endif (WIN32)

	if(QTDEPLOY)
		qt_generate_deploy_app_script(
			TARGET ${example}
			OUTPUT_SCRIPT deploy_script
			PRE_INCLUDE_REGEXES "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}*"
			)

		install(SCRIPT ${deploy_script})
	endif(QTDEPLOY)
	if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
		message(STATUS "Adding Test: ${example}" )
		add_test(NAME ${example} COMMAND ${example} https://https://api.testnet.shimmer.network ef4593558d0c3ed9e3f7a2de766d33093cd72372c800fa47ab5765c43ca006b5)
	endif(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
endforeach()

# Prepare Cpack to package the executables, headers and libraries
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
	set(CPACK_PACKAGE_CONTACT "estervtech")
	set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-v${SEMVER}-${CMAKE_SYSTEM_NAME}_${CMAKE_SYSTEM_VERSION}-${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_CXX_COMPILER_ID}")
	if(NOT BUILD_SHARED_LIBS)
		set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}-static")
	endif(NOT BUILD_SHARED_LIBS)
	if(USE_THREADS)
		set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}-MThread")
	endif(USE_THREADS)
	include(CPack)
endif(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
