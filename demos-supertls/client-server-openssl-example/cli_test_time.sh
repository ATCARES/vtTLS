for i in {0..50}
do
  ./client 172.17.39.6 test50m.txt >> result50m.txt;
  sleep 2;
done
