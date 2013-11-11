#!/usr/bin/env bash

set -e

MACHINE_TYPE=`uname -m`

if [ ${MACHINE_TYPE} == 'x86_64' ]; then
	echo x64
	FLINT_BINARY=flint_x64
else
	echo x86
	FLINT_BINARY=flint_x86
fi

find ./src/ -type d -name "*include*" | awk '{print "--i../." $0}'  > ./tools/FlexeLint/sdl-include-path.lnt

(git diff --name-only HEAD ; git ls-files --other --exclude-standard) | grep '.cc\|.cpp' | grep 'src/components\|src/appMain' | awk '{print "../../" $0}' > ./tools/FlexeLint/sdl-changed-modules.lnt

cd ./tools/FlexeLint/

./${FLINT_BINARY} -w1 -zero -u --i../../$1/src/components/ smartdevicelink-changes.lnt

rm ./sdl-include-path.lnt
rm ./sdl-changed-modules.lnt

