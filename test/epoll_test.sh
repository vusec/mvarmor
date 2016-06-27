sleep 0.1
curl -s http://localhost:1234/ >/dev/null
curl -s http://localhost:1234/ >/dev/null &
curl -s http://localhost:1234/a >/dev/null &
curl -s http://localhost:1234/b >/dev/null &
wait
kill -TERM $1
