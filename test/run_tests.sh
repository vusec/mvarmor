wrapper=$1
shift
for prog in "$@"; do
        printf "\n== Test $prog\n"
        MV_DONT_DETACH=1 MV_NUM_PROC=2 exec $wrapper ./$prog > "${prog}.out" &
        progpid=$!
        [ -f "${prog}_test.sh" ] && ./${prog}_test.sh $progpid
        wait
done
