macro(build_luajit LJ_VERSION)
    set(LJ_SOURCE_DIR ${PROJECT_BINARY_DIR}/luajit-${LJ_VERSION}/source)
    set(LJ_BINARY_DIR ${PROJECT_BINARY_DIR}/luajit-${LJ_VERSION}/work)
    set(LJ_PATCH_PATH ${PROJECT_SOURCE_DIR}/patches/luajit-v2.1.0.patch)

    include(ExternalProject)

    set(CFLAGS "-fPIC")

    ExternalProject_Add(patched-luajit
        GIT_REPOSITORY https://github.com/LuaJIT/LuaJIT
        GIT_TAG ${LJ_VERSION}
        GIT_PROGRESS TRUE
        SOURCE_DIR ${LJ_SOURCE_DIR}
        BINARY_DIR ${LJ_BINARY_DIR}/luajit-${LJ_VERSION}
        DOWNLOAD_DIR ${LJ_BINARY_DIR}
        TMP_DIR ${LJ_BINARY_DIR}/tmp
        STAMP_DIR ${LJ_BINARY_DIR}/stamp
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE

        PATCH_COMMAND patch -p1 -i ${LJ_PATCH_PATH}
        CONFIGURE_COMMAND ""
        BUILD_COMMAND cd <SOURCE_DIR> && $(MAKE) CC=${CMAKE_C_COMPILER} CFLAGS=${CFLAGS} -j
        INSTALL_COMMAND ""
        UPDATE_DISCONNECTED ON
    )

    set(LUA_FOUND TRUE)
    set(LUA_VERSION_STRING ${LJ_VERSION})
    set(LUA_INCLUDE_DIR ${LJ_SOURCE_DIR}/src/)
    set(LUA_LIBRARIES ${LJ_SOURCE_DIR}/src/libluajit.a)
    set(LUA_EXECUTABLE ${LJ_SOURCE_DIR}/src/luajit)

    unset(LJ_SOURCE_DIR)
    unset(LJ_BINARY_DIR)
endmacro(build_luajit)
