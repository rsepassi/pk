#!/usr/bin/env yash

: ${ROOTDIR:=$PWD}

. $ROOTDIR/scripts/stdsh.sh
stdsh_init

alicepk=DDF431F74343D77638F0B51112A9BACBF30344831269E6BA7A118364F499E9B3
alicesk=1AA6521724241D74F5892B69AA085114CCC1242E8CD756FCD8341974919A1A5DDDF431F74343D77638F0B51112A9BACBF30344831269E6BA7A118364F499E9B3
bobpk=5E656899DF2EB7ED7672044D667D7265CED3C8E9CE75E6F0294096BC9FF65370
bobsk=14BA2E68C3BD427628F998A235551FC50ABCB0B5B9AA0034C7A1C95093E394F05E656899DF2EB7ED7672044D667D7265CED3C8E9CE75E6F0294096BC9FF65370

chan=a1b2c3
disco=8899

make --silent -j
# ASAN=1
# export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:detect_invalid_pointer_pairs=2:detect_leaks=1
# export ASAN_SYMBOLIZER_PATH=/opt/homebrew/opt/llvm@19/bin/llvm-symbolizer
# export MIMALLOC_SHOW_STATS=1


# Disco, our support server
stdsh_go D ./build/out/bin/cli demo-disco disco -p${disco}

# Alice
stdsh_go A ./build/out/bin/cli demo-disco p2p -i \
  -p20000 -c${chan} -d":${disco}" -b${bobpk} -a${alicepk} -s${alicesk}

# Bob
stdsh_go B ./build/out/bin/cli demo-disco p2p \
  -p20001 -c${chan} -d":${disco}" -b${bobpk} -a${alicepk} -s${bobsk}

stdsh_tail_logs

stdsh_done
