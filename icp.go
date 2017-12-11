package dnsutils

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/valyala/fasthttp"
)

// IcpQuery query a url's icp info
func IcpQuery(domain string, n int) (map[string]interface{}, error) {
	url := "http://117.25.152.131:12345/beian?domain=" + domain
	rv := make(map[string]interface{})

	req := fasthttp.AcquireRequest()
	req.SetRequestURI(url)

	resp := fasthttp.AcquireResponse()
	client := &fasthttp.Client{}
	client.Do(req, resp)

	bodyBytes := resp.Body()
	switch {
	case bodyBytes == nil:
		return rv, errors.New("icp cloud interface is down")
	case string(bodyBytes) == "null":
		for i := 0; i < n; i++ {
			client.Do(req, resp)
			if bodyBytes := resp.Body(); string(bodyBytes) != "null" {
				json.Unmarshal(bodyBytes, &rv)
				return rv, nil
			}
		}
		return rv, fmt.Errorf("try %d times, but icp cloud interface return null", n)
	default:
		json.Unmarshal(bodyBytes, &rv)
		return rv, nil
	}
}
