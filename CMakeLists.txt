cmake_minimum_required (VERSION 3.1)

set(CMAKE_USER_MAKE_RULES_OVERRIDE_CXX ${CMAKE_CURRENT_SOURCE_DIR}/cxx_flag_overrides.cmake)

project (ionic-profiles)
set(CMAKE_CXX_STANDARD 11)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/target)

# attempt to find boost libraries
# use BOOST_ROOT to set the search location.. on windows we need explicit paths
set(Boost_USE_STATIC_LIBS ON)
if (NOT (platform STREQUAL "Windows" ) )
    find_package(Boost COMPONENTS regex system filesystem graph program_options REQUIRED)
elseif (NOT (BOOST_INCLUDEDIR AND BOOST_LIBRARYDIR))
    find_package(Boost COMPONENTS regex system filesystem graph program_options REQUIRED)
else()
    set(Boost_LIBRARY_DIRS "${BOOST_LIBRARYDIR}")
    set(Boost_INCLUDE_DIRS "${BOOST_INCLUDEDIR}")
endif()

include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

include_directories("$ENV{IONIC_SDK_PATH}/ISAgentSDKCpp/Include")
link_directories("$ENV{IONIC_SDK_PATH}/ISAgentSDKCpp/Lib/${platform}/Release/${architecture}")

include_directories("src")

# build ionic-profiles
file(GLOB IONIC_REGISTER_SOURCE src/*.cpp )
add_executable(ionic-profiles ${IONIC_REGISTER_SOURCE})

# link ionic sdk
set_target_properties(ionic-profiles PROPERTIES LINK_SEARCH_START_STATIC 1)
set_target_properties(ionic-profiles PROPERTIES LINK_SEARCH_END_STATIC 1)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

# osx specific
if ( platform STREQUAL "MacOSX" )
    target_link_libraries(ionic-profiles "boost_system")
    target_link_libraries(ionic-profiles "boost_filesystem")
    target_link_libraries(ionic-profiles "boost_program_options")
    target_link_libraries(ionic-profiles "boost_graph")
    target_link_libraries(ionic-profiles "ISAgentSDK")
    target_link_libraries(ionic-profiles
        "-framework CoreServices"
        "-framework CoreFoundation"
        "-framework IOKit"
        "-framework Security"
        "-framework Foundation"
    )
endif()

# linux specific
if ( platform STREQUAL "Linux" )
    target_link_libraries(ionic-profiles "boost_system")
    target_link_libraries(ionic-profiles "boost_filesystem")
    target_link_libraries(ionic-profiles "boost_program_options")
    target_link_libraries(ionic-profiles "boost_graph")
    target_link_libraries(ionic-profiles "ISAgentSDK")
    target_link_libraries(ionic-profiles
        "pthread"
        "curl"
        "stdc++"
        "m"
        "rt"
    )
    link_directories("/usr/lib")
endif()

# windows specific
if ( platform STREQUAL "Windows" )
    ADD_DEFINITIONS("-DBOOST_ALL_NO_LIB")
    target_link_libraries(ionic-profiles "libboost_system-vc140-mt-s-x32-1_66.lib")
    target_link_libraries(ionic-profiles "libboost_filesystem-vc140-mt-s-x32-1_66.lib")
    target_link_libraries(ionic-profiles "libboost_program_options-vc140-mt-s-x32-1_66.lib")
    target_link_libraries(ionic-profiles "ISAgentSDK")
endif()
