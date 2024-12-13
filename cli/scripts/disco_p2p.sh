#!/usr/bin/env yash

: ${ROOTDIR:=$PWD}

. $ROOTDIR/scripts/stdsh.sh
stdsh_init

alicepk=DDF431F74343D77638F0B51112A9BACBF30344831269E6BA7A118364F499E9B3
alicesk=1AA6521724241D74F5892B69AA085114CCC1242E8CD756FCD8341974919A1A5DDDF431F74343D77638F0B51112A9BACBF30344831269E6BA7A118364F499E9B3
bobpk=5E656899DF2EB7ED7672044D667D7265CED3C8E9CE75E6F0294096BC9FF65370
bobsk=14BA2E68C3BD427628F998A235551FC50ABCB0B5B9AA0034C7A1C95093E394F05E656899DF2EB7ED7672044D667D7265CED3C8E9CE75E6F0294096BC9FF65370

chan=n6jf2a
disco=8899

make --silent -j

# Disco, our support server
stdsh_go D ./build/out/bin/cli demo-disco disco -p${disco}
sleep 2  # let Disco come up before spawning A+B

# Alice
stdsh_go A ./build/out/bin/cli demo-disco p2p -i \
  -p20000 -c${chan} -d${disco} -b${bobpk} -a${alicepk} -s${alicesk}

# Bob
stdsh_go B ./build/out/bin/cli demo-disco p2p \
  -p20001 -c${chan} -d${disco} -b${bobpk} -a${alicepk} -s${bobsk}

stdsh_tail_logs

stdsh_done
