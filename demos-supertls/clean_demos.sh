# Bash script to clean all the demos before
# commiting to git

cd client-server-example
make clean

cd ../client-server-openssl-example
make clean

cd ../client-server-send-message
make clean
