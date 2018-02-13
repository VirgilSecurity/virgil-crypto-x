rm -rf "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"

case "${SWIFT_PLATFORM_TARGET_PREFIX}" in
    "ios")
        cp -R "VSCCrypto/PrebuiltFramework/iOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"

        if [ "${arch}" == "arm64" ]
        then
           lipo -remove i386 -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
           lipo -remove x86_64 -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
        else
           lipo -remove arm64 -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
           lipo -remove armv7 -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
           lipo -remove armv7s -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
        fi
    ;;
    "macosx")
        cp -R "VSCCrypto/PrebuiltFramework/macOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
    ;;
    "tvos")
        cp -R "VSCCrypto/PrebuiltFramework/tvOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"

        if [ "${arch}" == "arm64" ]
        then
           lipo -remove x86_64 -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
        else
           lipo -remove arm64 -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
        fi
    ;;
    "watchos")
        cp -R "VSCCrypto/PrebuiltFramework/watchOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"

        if [ "${arch}" == "armv7k" ]
        then
           lipo -remove i386 -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
        else
           lipo -remove armv7k -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
        fi
    ;;
esac
