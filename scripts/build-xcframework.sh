# export RUSTFLAGS="-C embed-bitcode=yes"
# export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_LINKER="/usr/bin/clang"
# export LIBRARY_PATH="//usr/lib"
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH="$HOME/.cargo/bin:$PATH"

REPO_ROOT=".."
RUST_FFI_DIR="../iroh-ffi"
OUT_DIR="../build"
RUST_TOOLCHAIN="1.71.0"

echo "Generate Iroh C header, copy Module map"
mkdir -p "${OUT_DIR}/include"
cargo +${RUST_TOOLCHAIN} test --features c-headers --manifest-path "${RUST_FFI_DIR}/Cargo.toml" -- generate_headers
cp ${RUST_FFI_DIR}/libiroh.h ${OUT_DIR}/include/iroh.h
cp ${REPO_ROOT}/swift/include/module.modulemap ${OUT_DIR}/include/module.modulemap

echo "Build Iroh Libraries for Apple Platforms"

targets=(
  "aarch64-apple-ios"
  "x86_64-apple-ios"
  "aarch64-apple-ios-sim"
)

for target in "${targets[@]}"; do
  cargo +`cat ${REPO_ROOT}/rust-toolchain` build --package iroh_ffi --release --target "${target}" --manifest-path "${RUST_FFI_DIR}/Cargo.toml"
  mkdir -p "${OUT_DIR}/lib_${target}"
  cp "${RUST_FFI_DIR}/target/${target}/release/libiroh.a" "${OUT_DIR}/lib_${target}/libiroh.a"
done

echo "Run Lipo"
mkdir -p "${OUT_DIR}/lib_ios-simulator-universal"
# cargo +`cat ${REPO_ROOT}/rust-toolchain` lipo \
#   --targets aarch64-apple-ios-sim,x86_64-apple-ios \
#   --manifest-path "${RUST_FFI_DIR}/Cargo.toml" 
# cp "${RUST_FFI_DIR}/target/universal/release/libiroh.a" "${OUT_DIR}/lib_ios-simulator-universal/libiroh.a"

lipo -create \
  "${OUT_DIR}/lib_x86_64-apple-ios/libiroh.a" \
  "${OUT_DIR}/lib_aarch64-apple-ios-sim/libiroh.a" \
  -output "${OUT_DIR}/lib_ios-simulator-universal/libiroh.a"
          

echo "Create XCFramework"

xcodebuild -create-xcframework \
  -library ${OUT_DIR}/lib_ios-simulator-universal/libiroh.a \
  -headers ${OUT_DIR}/include/ \
  -library ${OUT_DIR}/lib_aarch64-apple-ios/libiroh.a \
  -headers ${OUT_DIR}/include/ \
  -output ${REPO_ROOT}/LibIroh.xcframework BUILD_LIBRARY_FOR_DISTRIBUTION=YES

zip -r ${REPO_ROOT}/libiroh-xcframework.zip ${REPO_ROOT}/LibIroh.xcframework

echo "Done"