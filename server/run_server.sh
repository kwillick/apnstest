ROOT_CA_CERT="APNS-test-root-ca.cer"
CERT="APNS-test-ca-cert.pem"
KEY="APNS-test-ca-key.pem"

go run src/server.go --carootfile=$ROOT_CA_CERT --certfile=$CERT --keyfile=$KEY
