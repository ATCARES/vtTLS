for i in {0..50}
do
  ./client 172.17.39.6 test1m.txt >> result.txt;
  sleep 2;
done
