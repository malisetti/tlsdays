#!/bin/bash
ZIG=/work/home/.local/zig-linux-aarch64-0.13.0/zig
args=()
have_target=0
for arg in "$@"; do
  case "$arg" in
    --target=aarch64-unknown-linux-gnu)
      if [ "$have_target" -eq 0 ]; then
        args+=("-target" "aarch64-linux-gnu")
        have_target=1
      fi
      ;;
    --target=*)
      if [ "$have_target" -eq 0 ]; then
        t="${arg#--target=}"
        t="${t%-unknown-linux-gnu}"
        args+=("-target" "${t}-linux-gnu")
        have_target=1
      fi
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done
if [ "$have_target" -eq 0 ]; then
  args=("-target" "aarch64-linux-gnu" "${args[@]}")
fi
exec "$ZIG" cc "${args[@]}"
