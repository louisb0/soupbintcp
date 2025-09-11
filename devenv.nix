{pkgs, ...}: {
  languages.cplusplus.enable = true;

  packages = with pkgs; [
    alejandra
    include-what-you-use
    clang-tools
    valgrind
    gdb
  ];

  git-hooks.hooks = {
    alejandra = {
      enable = true;
      settings.check = true;
    };

    clang-format = {
      enable = true;
      entry = "${pkgs.clang-tools}/bin/clang-format --dry-run -Werror";
    };

    clang-tidy = {
      enable = true;
      entry = "${pkgs.clang-tools}/bin/clang-tidy -p build";
    };
  };

  scripts = {
    setup.exec = ''
      mkdir -p ~/.local/lib/wireshark/plugins/
      ln -sf $PWD/wireshark/dissector.lua ~/.local/lib/wireshark/plugins/dissector.lua

      BUILD_TYPE=''${1:-Debug}
      cmake -B build -S . -DCMAKE_BUILD_TYPE=$BUILD_TYPE
    '';

    build.exec = ''
      BUILD_TYPE=''${1:-Debug}
      setup $BUILD_TYPE
      cmake --build build
    '';

    clean.exec = ''
      rm -rf build/ .cache/
    '';

    iwyu.exec = ''
      output=$(iwyu_tool.py -p build src/ include/ examples/ 2>&1 | grep -v "no private include name for @headername mapping")
      echo "$output"
      echo "$output" | grep -q "should add these lines:" && exit 1 || exit 0
    '';
  };
}
