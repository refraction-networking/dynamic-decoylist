package analyser

import (
	"github.com/ammario/ipisp"
	"log"
	"net"
)

func GetCountryByIp(ip string) string{
	client, err := ipisp.NewDNSClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.LookupIP(net.ParseIP(ip))
	if err == nil && resp.Country != ""{
		return resp.Country
	} else {
		return "UNRESOLVED"
	}
}

func CheckEnd(candidate, standard string) bool {
	if len(candidate) < len(standard) {
		return false
	} else {
		for i := 0; i < len(standard); i++ {
			if standard[len(standard) - 1 -i] != candidate[len(candidate) - 1 - i] {
				return false
			}
		}
		return true
	}
}


