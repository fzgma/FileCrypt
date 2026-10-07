find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_BOTAN QUIET botan-3)
endif()
find_path(Botan_INCLUDE_DIR botan/version.h
    HINTS ${PC_BOTAN_INCLUDE_DIRS} PATH_SUFFIXES botan-3)
find_library(Botan_LIBRARY NAMES botan-3 botan
    HINTS ${PC_BOTAN_LIBRARY_DIRS})
if(Botan_INCLUDE_DIR)
    file(STRINGS "${Botan_INCLUDE_DIR}/botan/build.h" _botan_version
        REGEX "^#define BOTAN_VERSION_(MAJOR|MINOR|PATCH) ")
    foreach(_part MAJOR MINOR PATCH)
        string(REGEX MATCH "BOTAN_VERSION_${_part} +([0-9]+)" _match "${_botan_version}")
        set(_botan_${_part} "${CMAKE_MATCH_1}")
    endforeach()
    set(Botan_VERSION "${_botan_MAJOR}.${_botan_MINOR}.${_botan_PATCH}")
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Botan REQUIRED_VARS Botan_INCLUDE_DIR Botan_LIBRARY
    VERSION_VAR Botan_VERSION)
if(Botan_FOUND AND NOT TARGET Botan::Botan)
    add_library(Botan::Botan UNKNOWN IMPORTED)
    set_target_properties(Botan::Botan PROPERTIES
        IMPORTED_LOCATION "${Botan_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${Botan_INCLUDE_DIR}")
endif()
