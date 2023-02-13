macro(build_lua LUA_VERSION)

    if (${LUA_VERSION} EQUAL "5.1")
        set(LUA_MD5_HASH "2e115fe26e435e33b0d5c022e4490567")
        set(LUA_FULL_VERSION "5.1.5")
    elseif(${LUA_VERSION} EQUAL "5.2")
        set(LUA_MD5_HASH "913fdb32207046b273fdb17aad70be13")
        set(LUA_FULL_VERSION "5.2.4")
    elseif(${LUA_VERSION} EQUAL "5.3")
        set(LUA_MD5_HASH "83f23dbd5230140a3770d5f54076948d")
        set(LUA_FULL_VERSION "5.3.6")
    elseif(${LUA_VERSION} EQUAL "5.4")
        set(LUA_MD5_HASH "bd8ce7069ff99a400efd14cf339a727b")
        set(LUA_FULL_VERSION "5.4.4")
    endif()

    set(LUA_SOURCE_DIR ${PROJECT_BINARY_DIR}/lua-${LUA_VERSION}/source)
    set(LUA_BINARY_DIR ${PROJECT_BINARY_DIR}/lua-${LUA_VERSION}/work)
    set(LUA_PATCH_PATH ${PROJECT_SOURCE_DIR}/patches/lua-${LUA_FULL_VERSION}.patch)

    include(ExternalProject)

    ExternalProject_Add(patched-lua
        URL https://www.lua.org/ftp/lua-${LUA_FULL_VERSION}.tar.gz
        URL_MD5 ${LUA_MD5_HASH}
        SOURCE_DIR ${LUA_SOURCE_DIR}
        BINARY_DIR ${LUA_BINARY_DIR}
        DOWNLOAD_DIR ${LUA_BINARY_DIR}
        TMP_DIR ${LUA_BINARY_DIR}/tmp
        STAMP_DIR ${LUA_BINARY_DIR}/stamp
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE

        PATCH_COMMAND cd <SOURCE_DIR>/src && patch -p1 -i ${LUA_PATCH_PATH}
        CONFIGURE_COMMAND ""
        BUILD_COMMAND cd <SOURCE_DIR> && $(MAKE) -j generic
        INSTALL_COMMAND ""
        UPDATE_DISCONNECTED ON
    )

    set(LUA_FOUND TRUE)
    set(LUA_VERSION_STRING ${LUA_FULL_VERSION})
    set(LUA_INCLUDE_DIR ${LUA_SOURCE_DIR}/src/)
    set(LUA_LIBRARIES ${LUA_SOURCE_DIR}/src/liblua.a)
    set(LUA_EXECUTABLE ${LUA_SOURCE_DIR}/src/lua)

    unset(LUA_SOURCE_DIR)
    unset(LUA_BINARY_DIR)
    unset(LUA_PATCH_PATH)
endmacro(build_lua)
