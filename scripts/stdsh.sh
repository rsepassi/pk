STDSH_DIR=${STDSH_DIR:-$(mktemp -d -t stdsh)}

stdsh_init() {
  set -ex --pipe-fail
  trap stdsh_cleanup__ INT TERM EXIT
  echo 3 > $STDSH_DIR/nextfd
}

stdsh_done() {
  wait

  for pipe in $(ls $STDSH_DIR/*.pipe)
  do
    stdsh_cleanup_pipe__ $pipe
  done
  rm $STDSH_DIR/nextfd

  trap - INT TERM EXIT
  exit 0
}

stdsh_go() {
  tag=$1
  shift
  $@ 1>&2 2>$STDSH_DIR/$tag.log &
}

stdsh_pipe() {
  fd=$(cat $STDSH_DIR/nextfd)
  echo $((fd + 1)) > $STDSH_DIR/nextfd
  pipe=$STDSH_DIR/p${fd}.pipe
  mkfifo $pipe
  eval "exec ${fd}<>$pipe"
  echo $pipe
}

stdsh_pipe_close() {
  stdsh_cleanup_pipe__ $@
}

# a=(5 6 7 8)
# i=$(stdsh_arri 6 ${a[#]} ${a[*]})
# i is 2
stdsh_arri() {
  item=$1
  len=$2
  shift
  shift

  i=1
  while [ $i -le $len ]
  do
    if [ "$1" = "$item" ]
    then
      echo $i
      return
    fi

    i=$((i + 1))
    shift
  done

  echo -1
}

stdsh_tail_logs() {
  sleep 1  # let the log files be created before tailing
  tail -f $STDSH_DIR/*.log
}

stdsh_cleanup__() {
  kill $(jobs -p) 2>/dev/null
  wait

  for pipe in $(ls $STDSH_DIR/*.pipe)
  do
    stdsh_cleanup_pipe__ $pipe
  done
  rm $STDSH_DIR/nextfd

  exit
}

stdsh_cleanup_pipe__() {
  pipe=$1
  fd=${pipe#$STDSH_DIR/p}
  fd=${fd%.pipe}
  eval "exec $fd>&-"
  rm -f $pipe
}
