: ${TMPDIR:=/tmp}
STDSH_DIR=${STDSH_DIR:-$(mktemp -d $TMPDIR/stdsh_XXXXXX)}

stdsh_init() {
  set -e --pipe-fail
  trap stdsh_cleanup__ INT TERM EXIT
  echo 3 > $STDSH_DIR/nextfd
  if [ -n "$ROOTDIR" ]
  then
    rm -f $ROOTDIR/build/log
    mkdir -p $ROOTDIR/build
    ln -s $STDSH_DIR $ROOTDIR/build/log
  fi
  mkdir -p $STDSH_DIR/stdsh
}

stdsh_done() {
  set +e
  wait

  stdsh_cleanup_pipes__
  rm $STDSH_DIR/nextfd 2>/dev/null

  trap - INT TERM EXIT
  exit 0
}

stdsh_go() {
  tag=$1
  shift

  # Create the log file with the command line
  echo $@ > $STDSH_DIR/$tag.log

  # Create the actual script to run in the background
  cat <<EOF > $STDSH_DIR/stdsh/$tag.run
$@ 1>&2 2>>$STDSH_DIR/$tag.log
code=\$?
echo "exited \$code" >> $STDSH_DIR/$tag.log
echo \$code > "$STDSH_DIR/stdsh/$tag.exit"
EOF

  # Write out the background command so that the jobs list has a
  # variable-expanded name
  cat <<EOF > $STDSH_DIR/stdsh/$tag.run2
sh $STDSH_DIR/stdsh/$tag.run &
EOF

  # Source the background command file to actually run $tag.run &
  . $STDSH_DIR/stdsh/$tag.run2
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
  tail -f -n +1 $STDSH_DIR/*.log
}

stdsh_cleanup__() {
  set +e

  # Display still-running jobs
  jobs -lr

  kill $(jobs -p) 2>/dev/null
  wait

  stdsh_cleanup_pipes__
  rm $STDSH_DIR/nextfd 2>/dev/null

  exit
}

stdsh_cleanup_pipes__() {
  pipes=$(ls $STDSH_DIR/*.pipe 2>/dev/null)
  if [ -z "$pipes" ]; then return; fi
  for pipe in $pipes
  do
    stdsh_cleanup_pipe__ $pipe
  done
}

stdsh_cleanup_pipe__() {
  pipe=$1
  fd=${pipe#$STDSH_DIR/p}
  fd=${fd%.pipe}
  eval "exec $fd>&-"
  rm -f $pipe
}
