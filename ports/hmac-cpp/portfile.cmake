vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO NewYaroslav/hmac-cpp
    REF v0.5.0
    SHA512 a4e4b137ea6dab0ae22990ba0c9c45a290e51dd454b1e5865c7e918dc53896388427deb0c1aa92936c8f36ef908d1fed1066c4dc77703401ef9e14b7c1dc0697
)

vcpkg_cmake_configure(
    SOURCE_PATH ${SOURCE_PATH}
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(
    CONFIG_PATH lib/cmake/hmac_cpp
)

vcpkg_fixup_pkgconfig()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(
    FILE_LIST "${SOURCE_PATH}/LICENSE"
)
