find_package(PkgConfig QUIET)
option(Botan_USE_STATIC_LIBS "使用 Botan 静态库及其传递依赖" OFF)
if(Botan_USE_STATIC_LIBS AND UNIX)
    # 静态发布必须读取同一安装前缀的 .pc 文件，不能丢失传递依赖。
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PC_BOTAN REQUIRED botan-3)
endif()
if(PkgConfig_FOUND AND NOT Botan_USE_STATIC_LIBS)
    pkg_check_modules(PC_BOTAN QUIET botan-3)
endif()
find_path(Botan_INCLUDE_DIR botan/version.h
    HINTS ${PC_BOTAN_INCLUDE_DIRS} PATH_SUFFIXES botan-3)
if(Botan_USE_STATIC_LIBS AND UNIX)
    set(_botan_library_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()
find_library(Botan_LIBRARY NAMES botan-3 botan HINTS ${PC_BOTAN_LIBRARY_DIRS})
if(Botan_USE_STATIC_LIBS AND UNIX)
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${_botan_library_suffixes}")
    if(Botan_LIBRARY AND NOT Botan_LIBRARY MATCHES "\\.a$")
        message(FATAL_ERROR "Botan 静态发布需要 .a 库；请清除旧的 Botan_LIBRARY 缓存")
    endif()
endif()
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
    if(Botan_USE_STATIC_LIBS AND UNIX)
        set(_botan_dependencies ${PC_BOTAN_STATIC_LIBRARIES})
        list(REMOVE_ITEM _botan_dependencies botan-3 botan)
        set_target_properties(Botan::Botan PROPERTIES
            INTERFACE_LINK_LIBRARIES "${_botan_dependencies}"
            INTERFACE_LINK_DIRECTORIES "${PC_BOTAN_STATIC_LIBRARY_DIRS}"
            INTERFACE_LINK_OPTIONS "${PC_BOTAN_STATIC_LDFLAGS_OTHER}")
    elseif(Botan_USE_STATIC_LIBS AND WIN32)
        # Windows 发布由静态 vcpkg triplet 提供 .lib，补齐 Botan 的系统依赖。
        set_target_properties(Botan::Botan PROPERTIES
            INTERFACE_LINK_LIBRARIES "bcrypt;crypt32;ws2_32;advapi32;user32")
    endif()
endif()
