ROOT_CA_CERT="APNS-test-root-ca.cer"
CERT="APNS-test-client-cert.pem"
KEY="APNS-test-client-key.pem"
export GOPATH=`pwd`

go get github.com/kwillick/apns

go run src/client.go --carootfile=$ROOT_CA_CERT --certfile=$CERT --keyfile=$KEY
