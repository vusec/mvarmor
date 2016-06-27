sleep 0.1
echo "test" | nc -u 127.0.0.1 1234 >/dev/null &
ncpid=$!
sleep 0.1
kill $ncpid
