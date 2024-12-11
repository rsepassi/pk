STDSH_LOGDIR=${LOGDIR:-/tmp/stdsh_logs}

stdsh_init() {
  rm -rf $STDSH_LOGDIR
  mkdir -p $STDSH_LOGDIR
  set -ex --pipe-fail
  trap stdsh_cleanup INT TERM EXIT
}

stdsh_done() {
  wait
  trap - INT TERM EXIT
  exit 0
}

stdsh_cleanup() {
  kill $(jobs -p) 2>/dev/null
  wait
  exit
}

stdsh_go() {
  tag=$1
  shift
  $@ 1>&2 2>$STDSH_LOGDIR/$tag.log &
}

stdsh_tail_logs() {
  sleep 1  # let the log files be created before tailing
  tail -f $STDSH_LOGDIR/*.log
}
