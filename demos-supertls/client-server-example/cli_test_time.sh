for i in {0..50}
do
  echo 'Test' +  $i + ' of 50'
  ./client 172.17.39.2 100MB.zip >> 100MB_result.txt;
  sleep 1;
done
