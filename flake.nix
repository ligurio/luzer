{
  description = "coverage-guided, native Lua fuzzing engine";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = pkgs.lib;

        # LuaJIT build is a special case: CMake configures it with
        # -DENABLE_LUAJIT=ON and resolves it via pkg-config.
        isLuaJIT = lua: lib.hasPrefix "luajit" lua.name;

        # Build luzer against a concrete Lua implementation.
        # PUC-Rio Lua versions are passed to CMake through
        # CMAKE_LUA_INCLUDE_DIR and CMAKE_LUA_LIBRARIES (see the
        # first branch in CMakeLists.txt).
        buildLuzer = lua:
          pkgs.llvmPackages_latest.stdenv.mkDerivation {
            pname = "luzer";
            version = "scm-1";

            src = self.outPath;

            nativeBuildInputs = with pkgs; [ cmake ninja pkg-config ];
            buildInputs = [ lua ];

            hardeningDisable = [ "fortify" ];

            cmakeFlags = [
              "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
              "-DCMAKE_LIBDIR=${placeholder "out"}/lib"
              "-DCMAKE_LUADIR=${placeholder "out"}/share/lua/${lua.luaversion}"
              "-DENABLE_TESTING=OFF"
            ] ++ lib.optionals (isLuaJIT lua) [
              "-DENABLE_LUAJIT=ON"
              "-DLUAJIT_FRIENDLY_MODE=ON"
            ] ++ lib.optionals (!isLuaJIT lua) [
              "-DCMAKE_LUA_INCLUDE_DIR=${lua}/include"
              "-DCMAKE_LUA_LIBRARIES=${lua}/lib/liblua.so"
            ];

            meta = {
              description = "A coverage-guided, native Lua fuzzing engine";
              homepage = "https://github.com/ligurio/luzer";
              license = lib.licenses.isc;
              platforms = lib.platforms.all;
            };
          };

        # A development shell that is able to build luzer against
        # the selected Lua implementation.
        mkDevShell = lua:
          pkgs.mkShell.override { stdenv = pkgs.llvmPackages_latest.stdenv; } {
            hardeningDisable = [ "fortify" ];

            nativeBuildInputs = with pkgs; [
              clang
              cmake
              ninja
              gnumake
              pkg-config
            ] ++ [
              pkgs.llvmPackages_latest.clang-tools
              pkgs.llvmPackages_latest.clang
              pkgs.llvmPackages_latest.clangUseLLVM
            ];

            buildInputs = [ lua ]
              ++ lib.optional (lua ? pkgs && lua.pkgs ? lua-protobuf)
                lua.pkgs.lua-protobuf;

            shellHook =
              let
                luaLibrary = if isLuaJIT lua
                  then "${lua}/lib/libluajit-5.1.so"
                  else "${lua}/lib/liblua.so";
              in
              ''
                export HARDENING_ENABLE=""

                export PKG_CONFIG_PATH="${lua}/lib/pkgconfig"
                export CMAKE_PREFIX_PATH="${lua}"
                export Lua_ROOT="${lua}"
                export Lua_INCLUDE_DIR="${lua}/include"
                export Lua_LIBRARY="${luaLibrary}"
                export PATH="${lua}/bin:$PATH"

                echo "Lua: $(lua -v)"
                echo "Lua root: $Lua_ROOT"
                echo "Lua include dir: $Lua_INCLUDE_DIR"
                echo "Lua library: $Lua_LIBRARY"
              '' + (if isLuaJIT lua then ''
                echo "Configure: cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_LUAJIT=ON -DLUAJIT_FRIENDLY_MODE=ON"
              '' else ''
                echo "Configure: cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_LUA_INCLUDE_DIR=\"$Lua_INCLUDE_DIR\" -DCMAKE_LUA_LIBRARIES=\"$Lua_LIBRARY\""
              '');
          };

        luaVersions = {
          lua51 = pkgs.lua5_1;
          lua52 = pkgs.lua5_2;
          lua53 = pkgs.lua5_3;
          lua54 = pkgs.lua5_4;
          lua55 = pkgs.lua5_5;
          luajit = pkgs.luajit;
        };

        defaultLuaName = "luajit";
      in
      {
        packages = lib.mapAttrs (name: lua: buildLuzer lua) luaVersions
          // { default = buildLuzer luaVersions.${defaultLuaName}; };

        devShells = lib.mapAttrs (name: lua: mkDevShell lua) luaVersions
          // { default = mkDevShell luaVersions.${defaultLuaName}; };
      }
    );
}
