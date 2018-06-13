diff(){
  awk 'BEGIN{RS=ORS=" "}
       {NR==FNR?a[$0]++:a[$0]--}
       END{for(k in a)if(a[k])print k}' <(echo -n "${!1}") <(echo -n "${!2}")
}

containsElement () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

rm -rf "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"

case "${SWIFT_PLATFORM_TARGET_PREFIX}" in
    "ios")
        cp -R "VSCCrypto/PrebuiltFramework/iOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
    ;;
    "macosx")
        cp -R "VSCCrypto/PrebuiltFramework/macOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
    ;;
    "tvos")
        cp -R "VSCCrypto/PrebuiltFramework/tvOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
    ;;
    "watchos")
        cp -R "VSCCrypto/PrebuiltFramework/watchOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
    ;;
esac

LIPO_OUTPUT="$(lipo -info "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}")"
echo "LIPO_OUTPUT: ${LIPO_OUTPUT}"
PREFIX="Architectures in the fat file: ${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME} are: "
LIPO_CLEAN_OUTPUT=${LIPO_OUTPUT#$PREFIX}
echo "LIPO_CLEAN_OUTPUT: ${LIPO_CLEAN_OUTPUT}"
INCLUDED_ARCHS=( $LIPO_CLEAN_OUTPUT )
echo "INCLUDED_ARCHS: ${INCLUDED_ARCHS[@]}"
echo "VALID_ARCHS: ${VALID_ARCHS[@]}"

ARCHS_TO_EXCLUDE=$(diff INCLUDED_ARCHS[@] VALID_ARCHS[@])
echo "ARCHS_TO_EXCLUDE: ${ARCHS_TO_EXCLUDE[@]}"

for EXCLUDE_ARCH in ${ARCHS_TO_EXCLUDE[@]}
do
  if containsElement $EXCLUDE_ARCH ${INCLUDED_ARCHS[@]}; then
      echo "Excluding ${EXCLUDE_ARCH}"
      lipo -remove $EXCLUDE_ARCH -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
  fi
done